package server

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed login.html
var loginPageHTML string

var loginPage = template.Must(template.New("login").Parse(loginPageHTML))

// maxLoginFormBytes caps the login form body; it only ever carries a key and
// a return path.
const maxLoginFormBytes = 64 << 10

// loginPageData is what login.html renders.
type loginPageData struct {
	Next  string
	Error string
}

// renderLogin writes the login page. It is a server-rendered form rather than
// part of the UI because the UI's own files sit behind auth, and because a
// plain HTML form with autocomplete hints is what password managers recognize
// most reliably.
func renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = loginPage.Execute(w, data)
}

// handleLoginPage serves the login form at <prefix>/ui/login. A browser that
// already holds a valid session goes straight on to where it was headed.
func (sa *sessionAuth) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if state, _ := sa.check(r); state == sessionValid {
		redirectRelative(w, loginReturnPath(next), http.StatusSeeOther)
		return
	}
	renderLogin(w, http.StatusOK, loginPageData{Next: next})
}

// handleLogin checks the submitted API key and, when it matches one of
// apiKeys, sets the session cookie and returns the browser to where it was
// headed. A submitted username is ignored, the same as the username of Basic
// auth.
func (sa *sessionAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	// These handlers sit outside the auth middleware, so they need their own
	// check that the form was posted from this llama-swap's login page.
	if !sameOriginRequest(r) {
		http.Error(w, "llama-swap: cross-origin login rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "llama-swap: invalid login form", http.StatusBadRequest)
		return
	}

	next := r.PostForm.Get("next")
	// Trimmed because a key pasted by hand often brings a stray newline. Header
	// keys are not trimmed, which is safe: the loader rejects keys with spaces.
	key, ok := matchAPIKey(sa.keys, strings.TrimSpace(r.PostForm.Get("password")))
	if !ok {
		renderLogin(w, http.StatusUnauthorized, loginPageData{Next: next, Error: "That API key is not valid."})
		return
	}

	http.SetCookie(w, sa.newCookie(r, key))
	redirectRelative(w, loginReturnPath(next), http.StatusSeeOther)
}

// handleLogout clears this instance's session cookies and returns the browser
// to the login page. The browser also sends the cookies of other instances on
// the same host, since cookies ignore the port; those are left alone.
func (sa *sessionAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		http.Error(w, "llama-swap: cross-origin logout rejected", http.StatusForbidden)
		return
	}
	for _, c := range r.Cookies() {
		if _, ours := sa.byCookie[c.Name]; ours {
			http.SetCookie(w, &http.Cookie{
				Name:     c.Name,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   requestIsHTTPS(r),
			})
		}
	}
	redirectRelative(w, "login", http.StatusSeeOther)
}
