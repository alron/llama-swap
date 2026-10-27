package config

import (
	"fmt"
	"net/url"
	"strings"
)

// CORSWildcardOrigin allows any origin. It is the default when
// security.cors.allowedOrigins is empty, which keeps an absent security block
// behaving exactly like llama-swap did before the setting existed.
const CORSWildcardOrigin = "*"

// DefaultCORSMaxAge is the Access-Control-Max-Age value sent on preflight
// responses when security.cors.maxAge is not set.
const DefaultCORSMaxAge = 86400

// DefaultCORSAllowedOrigins returns the default allowedOrigins list. The
// returned slice is fresh so callers may mutate it without affecting other
// configs.
func DefaultCORSAllowedOrigins() []string {
	return []string{CORSWildcardOrigin}
}

// DefaultCORSAllowedMethods returns the methods advertised on a preflight
// response when security.cors.allowedMethods is not set.
func DefaultCORSAllowedMethods() []string {
	return []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
}

// DefaultCORSAllowedHeaders returns the request headers advertised on a
// preflight response when the client sent no Access-Control-Request-Headers
// and security.cors.allowedHeaders is not set.
func DefaultCORSAllowedHeaders() []string {
	return []string{"Content-Type", "Authorization", "Accept", "X-Requested-With"}
}

// Values for security.auth.mode.
const (
	// AuthModeBasic answers a browser missing an API key with a Basic auth
	// challenge, which makes it show its native login dialog.
	AuthModeBasic = "basic"
	// AuthModeForm sends a browser missing an API key to a login page that
	// exchanges the key for a session cookie. Browsers never see a Basic
	// challenge in this mode, and Basic credentials they send are ignored.
	AuthModeForm = "form"
)

// DefaultSessionTTL is the security.auth.sessionTTL used when it is not set:
// seven days, in seconds.
const DefaultSessionTTL = 7 * 24 * 60 * 60

// DefaultSessionMaxLifetime is the security.auth.sessionMaxLifetime used when
// it is not set: thirty days, in seconds.
const DefaultSessionMaxLifetime = 30 * 24 * 60 * 60

// SecurityConfig groups settings that control who may talk to llama-swap.
type SecurityConfig struct {
	CORS CORSConfig `yaml:"cors"`
	Auth AuthConfig `yaml:"auth"`
}

// AuthConfig controls how a browser is asked for one of the apiKeys. API
// clients are unaffected by the choice: a key sent as Bearer, x-api-key or
// Basic auth works in either mode. Only browsers change, and in form mode they
// log in through the form rather than with Basic auth.
type AuthConfig struct {
	// Mode is AuthModeBasic (the default) or AuthModeForm. Form mode requires
	// apiKeys, since there is otherwise nothing to log in with.
	Mode string `yaml:"mode"`

	// SessionTTL is how long in seconds a form login lasts without being
	// used. Using it renews the session, up to SessionMaxLifetime. 0 means
	// DefaultSessionTTL. Ignored in basic mode.
	SessionTTL int `yaml:"sessionTTL"`

	// SessionMaxLifetime caps in seconds how long one login can be kept alive
	// by renewal, counted from when the browser logged in. 0 means no cap.
	// It is a pointer so an absent key (nil, DefaultSessionMaxLifetime) and
	// an explicit 0 can be told apart. Ignored in basic mode.
	SessionMaxLifetime *int `yaml:"sessionMaxLifetime"`

	// SessionSecret signs form login sessions. Empty means a random secret
	// generated when llama-swap starts, so a restart logs every browser out.
	// Setting it keeps sessions across restarts, and instances that share it
	// and a key share a login. Changing it logs every browser out without
	// touching the apiKeys API clients use. Ignored in basic mode.
	SessionSecret string `yaml:"sessionSecret"`
}

// MaxSessionSeconds bounds sessionTTL and sessionMaxLifetime. Ten years is
// far beyond any useful session and far below the roughly 292 years at which
// the lifetimes overflow time.Duration.
const MaxSessionSeconds = 10 * 365 * 24 * 60 * 60

// MinSessionSecretLength is the shortest security.auth.sessionSecret accepted.
// The secret is all that stops a leaked session cookie from being used to
// test API key guesses offline, so it must not be guessable itself.
const MinSessionSecretLength = 32

// Validate reports an unknown mode, a negative or inconsistent session
// lifetime, or a short session secret. Defaults are applied by the loader
// before this runs.
func (c AuthConfig) Validate() error {
	switch c.Mode {
	case AuthModeBasic, AuthModeForm:
	default:
		return fmt.Errorf("mode: %q is not valid, use %q or %q", c.Mode, AuthModeBasic, AuthModeForm)
	}
	if c.SessionTTL < 0 {
		return fmt.Errorf("sessionTTL must be >= 0")
	}
	if c.SessionTTL > MaxSessionSeconds {
		return fmt.Errorf("sessionTTL must be at most %d (10 years)", MaxSessionSeconds)
	}
	if maxLifetime := c.SessionMaxLifetime; maxLifetime != nil {
		if *maxLifetime < 0 {
			return fmt.Errorf("sessionMaxLifetime must be >= 0")
		}
		if *maxLifetime > MaxSessionSeconds {
			return fmt.Errorf("sessionMaxLifetime must be at most %d (10 years); use 0 for no cap", MaxSessionSeconds)
		}
		// A cap below the session length would silently shorten every
		// login, which is more likely a mistake than the intent.
		if *maxLifetime > 0 && *maxLifetime < c.SessionTTL {
			return fmt.Errorf("sessionMaxLifetime (%d) is shorter than sessionTTL (%d); raise it, or set 0 for no cap", *maxLifetime, c.SessionTTL)
		}
	}
	if c.SessionSecret != "" && len(c.SessionSecret) < MinSessionSecretLength {
		return fmt.Errorf("sessionSecret must be at least %d characters; generate one with: head -c 32 /dev/urandom | base64", MinSessionSecretLength)
	}
	return nil
}

// FormLoginEnabled reports whether browsers log in through the login form.
// The loader already rejects form mode without apiKeys; checking the keys here
// too keeps a Config built directly in Go from serving a login nothing passes.
func (c Config) FormLoginEnabled() bool {
	return c.Security.Auth.Mode == AuthModeForm && len(c.RequiredAPIKeys) > 0
}

// CORSConfig controls the Access-Control-* headers llama-swap sends.
//
// AllowedOrigins selects between two modes. Leaving it empty keeps the
// permissive policy llama-swap had before the setting existed, so configs
// written without it are unaffected. Setting it means taking charge of who may
// reach llama-swap from a browser, and nothing then widens access beyond the
// list; write "*" to allow any origin deliberately. The remaining fields
// describe preflight mechanics rather than access, so each one left empty
// still takes its default and a config naming only origins keeps working.
//
// See issues #85, #1121 and #1133 — llama-swap must be the only source of
// these headers, because upstreams such as llama-server set their own and
// httputil.ReverseProxy adds rather than replaces them.
type CORSConfig struct {
	// AllowedOrigins lists the browser origins that may read responses, and
	// selects the mode: absent means the permissive legacy policy, present
	// means only these origins. It is required once any other field here is
	// set, and writing it as an empty list is rejected rather than read as
	// "allow everything". A "*" entry allows any origin and cannot be
	// combined with AllowCredentials.
	//
	// Nil and empty are therefore different: yaml.v3 leaves this nil for an
	// absent key and produces a non-nil empty slice for `allowedOrigins: []`,
	// which is what lets Validate tell them apart.
	AllowedOrigins []string `yaml:"allowedOrigins"`

	// AllowCredentials sends Access-Control-Allow-Credentials: true, letting
	// the browser attach cookies and Authorization headers.
	AllowCredentials bool `yaml:"allowCredentials"`

	// AllowPrivateNetwork answers Chrome's Private Network Access preflight
	// with Access-Control-Allow-Private-Network: true, letting a page on a
	// public origin reach llama-swap on a private address. Off by default,
	// and cannot be combined with a "*" origin: that pairing would let any
	// page in any open tab drive a llama-swap on the user's own network,
	// which is what Private Network Access exists to prevent.
	AllowPrivateNetwork bool `yaml:"allowPrivateNetwork"`

	// AllowedMethods is advertised on preflight responses. Empty means
	// DefaultCORSAllowedMethods.
	AllowedMethods []string `yaml:"allowedMethods"`

	// AllowedHeaders is advertised on preflight responses. Empty means the
	// client's sanitized Access-Control-Request-Headers is echoed back,
	// falling back to DefaultCORSAllowedHeaders when it sent none.
	AllowedHeaders []string `yaml:"allowedHeaders"`

	// ExposedHeaders lists response headers a browser may read beyond the
	// CORS-safelisted set. Empty omits the header.
	ExposedHeaders []string `yaml:"exposedHeaders"`

	// MaxAge is the preflight cache lifetime in seconds. 0 means
	// DefaultCORSMaxAge.
	MaxAge int `yaml:"maxAge"`
}

// Validate reports configuration that cannot produce a usable CORS policy.
func (c CORSConfig) Validate() error {
	if len(c.AllowedOrigins) == 0 {
		// A nil slice means the key was never written, which selects the
		// legacy permissive policy. A non-nil empty one means the key is
		// there as `allowedOrigins: []`, and allowing every origin because
		// someone asked for none would invert what they wrote.
		if c.AllowedOrigins != nil {
			return fmt.Errorf(`allowedOrigins must list at least one origin, or "*" to allow any; remove the key to keep the permissive default`)
		}
		if !c.hasNonOriginSettings() {
			// Nothing configured at all, which selects the legacy permissive
			// policy and needs no further checking.
			return nil
		}
		// Falling back to allow-all here would widen access for a config that
		// plainly meant to restrict something, and would pair
		// allowCredentials with a wildcard origin, which the Fetch spec
		// forbids.
		return fmt.Errorf("allowedOrigins is required when any other cors setting is present; remove the security.cors block to keep the permissive default")
	}

	for _, origin := range c.AllowedOrigins {
		if origin == CORSWildcardOrigin {
			if c.AllowCredentials {
				return fmt.Errorf(`allowedOrigins may not contain "*" when allowCredentials is true; list the origins explicitly`)
			}
			if c.AllowPrivateNetwork {
				return fmt.Errorf(`allowedOrigins may not contain "*" when allowPrivateNetwork is true; list the origins explicitly`)
			}
			continue
		}
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
	}

	for _, m := range c.AllowedMethods {
		if !IsHTTPToken(m) {
			return fmt.Errorf("allowedMethods: %q is not a valid HTTP method", m)
		}
	}
	for _, h := range c.AllowedHeaders {
		if !IsHTTPToken(h) {
			return fmt.Errorf("allowedHeaders: %q is not a valid HTTP header name", h)
		}
	}
	for _, h := range c.ExposedHeaders {
		if !IsHTTPToken(h) {
			return fmt.Errorf("exposedHeaders: %q is not a valid HTTP header name", h)
		}
	}

	if c.MaxAge < 0 {
		return fmt.Errorf("maxAge must be >= 0")
	}

	return nil
}

// hasNonOriginSettings reports whether any field other than AllowedOrigins
// carries a non-zero value, which is how a half-written block is recognized.
func (c CORSConfig) hasNonOriginSettings() bool {
	return c.AllowCredentials ||
		c.AllowPrivateNetwork ||
		len(c.AllowedMethods) > 0 ||
		len(c.AllowedHeaders) > 0 ||
		len(c.ExposedHeaders) > 0 ||
		c.MaxAge != 0
}

// validateCORSOrigin checks that an entry is a bare scheme://host[:port], the
// only form a browser ever sends in an Origin header. A trailing slash or a
// path would silently never match, so reject it at load time.
func validateCORSOrigin(origin string) error {
	if origin == "" {
		return fmt.Errorf("allowedOrigins: entry must not be empty")
	}
	if origin != strings.TrimSpace(origin) {
		return fmt.Errorf("allowedOrigins: %q must not have leading or trailing whitespace", origin)
	}

	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("allowedOrigins: %q is not a valid origin: %w", origin, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("allowedOrigins: %q must be a scheme://host[:port] origin, e.g. https://dashboard.example.com", origin)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("allowedOrigins: %q must not include a path, query, fragment or userinfo", origin)
	}

	return nil
}

// IsHTTPToken reports whether s is a non-empty RFC 9110 token, the grammar
// both method names and header names follow. It is exported because
// internal/server sanitizes Access-Control-Request-Headers with the same rule
// and cannot import swaputil, which already depends on this package.
func IsHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isTokenChar(r) {
			return false
		}
	}
	return true
}

// isTokenChar reports whether r is valid in an RFC 9110 token.
func isTokenChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
	case r >= 'A' && r <= 'Z':
	case r >= '0' && r <= '9':
	case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
	default:
		return false
	}
	return true
}
