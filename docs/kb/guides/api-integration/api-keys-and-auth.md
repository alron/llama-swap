---
title: API keys, access control, and keeping secrets out of your config
summary: apiKeys authentication has no per-key rate limits or user permissions; use env macros for secrets; security.auth.mode form gives browsers a login page.
category: guides
tags: [security, api-keys, auth, secrets, env, rate-limit, users, permissions, access-control, login, password-manager, session, cookie]
config_keys: [apiKeys, macros, peers.*.apiKey, models.*.env, security.auth.mode, security.auth.sessionTTL, security.auth.sessionMaxLifetime, security.auth.sessionSecret]
updated: 2026-10-27
---

# API keys and keeping secrets out of your config

## Requiring a key

By default llama-swap is unauthenticated. Add `apiKeys` and every request needs
one:

```yaml
apiKeys:
  - "sk-hunter2"
```

Clients may present it as `Authorization: Bearer <key>`, `x-api-key: <key>`, or
HTTP Basic. The web UI and everything under `/api/` are covered too.

A handful of static files stay reachable without a key regardless:
`/favicon.ico`, `/ui/site.webmanifest`, and the two icons it references
(`/ui/web-app-manifest-192x192.png`, `/ui/web-app-manifest-512x512.png`).
Browsers fetch all of these themselves — the favicon for the tab, the
manifest and its icons to decide whether to offer installing llama-swap as a
PWA — and have no way to attach your API key to those requests.

Generate a real one:

```console
$ printf "sk-%s\n" "$(head -c 48 /dev/urandom | base64)"
```

Multiple keys are allowed, which is how you rotate without downtime: add the
new key, move clients over, remove the old one.

All keys are equivalent. llama-swap has no per-key rate limiting, user
accounts, roles, or per-key permissions. Put a reverse proxy or API gateway in
front of llama-swap when you need those controls.

**`apiKeys` is not a substitute for a firewall.** llama-swap starts processes
on your machine. Do not expose it to the internet on the strength of a bearer
token alone.

## Logging in from a browser

By default a browser without a key gets a Basic auth challenge and shows its
native login dialog; the key goes in the password field. Password managers
often fail to fill that dialog. Form mode replaces it with a login page:

```yaml
apiKeys:
  - "${env.LLAMA_SWAP_KEY}"
security:
  auth:
    mode: form                 # default: basic
    sessionTTL: 604800         # idle timeout in seconds, default 7 days
    sessionMaxLifetime: 2592000 # cap from login, default 30 days; 0 = no cap
```

Opening the UI now redirects to `/ui/login`. Enter one of the `apiKeys` as the
API key. A successful login sets a session cookie, and the sidebar gets a
logout button.

API clients are unaffected: `Authorization: Bearer`, `x-api-key` and Basic auth
keep working, and a request without a key still gets the Basic challenge.
Browsers never see the Basic dialog in form mode, not even from an upstream or
peer, and Basic credentials a browser sends are ignored. Otherwise a browser
that cached them, say from before you switched to form mode, would stay logged
in after logging out.

A request counts as a browser's when it carries `Sec-Fetch-*`, `Origin` or
`Referer` headers or a session cookie, or asks for HTML. A script that sends
Basic auth along with such headers is treated as a browser too; give it
`Authorization: Bearer` instead.

Things to know:

- **Form mode requires `apiKeys`.** Without a key the config fails to load.
- **A session lasts while it is used.** Using the UI renews it once less than
  half of `sessionTTL` is left, so `sessionTTL` is how long a browser stays
  logged in without being used. Renewal stops at `sessionMaxLifetime` after
  login (`0` removes the cap). The UI's event stream does not count, but pages
  that poll do, so a tab left open on one keeps the session alive up to the
  cap. When a session ends, any request still running is cut off and the UI
  returns to the login page.
- **A restart logs browsers out; a config reload does not.** Sessions are
  signed with a secret generated at startup. Set `sessionSecret` (32+
  characters, ideally `${env.*}`) to keep them across restarts. Changing it, or
  removing the key a browser logged in with, logs that browser out without
  affecting API clients. Logging out only clears that browser's cookie.
- **Each instance has its own login.** Cookies ignore the port, so instances on
  one host see each other's cookies, but each accepts only its own. Instances
  share a login only when they share both `sessionSecret` and the key.
- **The session only works from this instance's own pages.** Requests that a
  page on another site or port makes the browser send get a 403, and
  `GET /unload` always needs an API key in a header. Links from elsewhere still
  open the UI, and a link to `/upstream/<model>/` still loads that model.
- **Plain HTTP on a LAN address is less strict.** Browsers send their
  `Sec-Fetch-*` headers only over HTTPS and to localhost. Without them
  llama-swap checks `Origin` and `Referer` instead, but cannot tell a page
  framed by another port on the same host from a normal page load. Use HTTPS
  or localhost for full protection.
- **A peer that wants a login gives a 502.** When a peer is another llama-swap
  in form mode and `peers.<id>.apiKey` is missing or wrong, its pages answer
  with a 502 naming that setting instead of a login page.
- **Behind a plain-HTTP reverse proxy, pass the host through.** Those checks
  compare `Origin`/`Referer` with `Host` or `X-Forwarded-Host`. A proxy that
  rewrites `Host` and sets neither (nginx's default) makes login fail with a
  403; with nginx, add `proxy_set_header Host $http_host;`.
- **The login does not stick over plain HTTP if the proxy says HTTPS.** The
  cookie is marked `Secure` when llama-swap serves TLS itself or a proxy sends
  `X-Forwarded-Proto: https`, and browsers then refuse to send it over plain
  HTTP.
- **The UI cannot be embedded in another site's frame.** The login page
  refuses to be framed, and over HTTPS or localhost the session is refused
  inside one.

## Keep the keys out of the file

Use env macros so the config itself is safe to commit:

```yaml
apiKeys:
  - "${env.LLAMA_SWAP_KEY}"
  - "${env.LLAMA_SWAP_KEY_ROTATE}"
```

`${env.VAR}` is substituted before anything else. **If the variable is not set,
config loading fails with an error** — which is what you want. A typo becomes a
startup failure rather than an instance running with an empty key list.

The same applies anywhere a secret appears:

```yaml
peers:
  openrouter:
    proxy: https://openrouter.ai/api
    apiKey: ${env.OPENROUTER_API_KEY}
    models: [z-ai/glm-4.7, moonshotai/kimi-k2-0905]

models:
  hf-model:
    env:
      - "HF_TOKEN=${env.HF_TOKEN}"
    cmd: llama-server --port ${PORT} -hf some/repo
```

## How peer keys are used

`peers.*.apiKey` is injected into outgoing requests to that peer, as **both**
`Authorization: Bearer <key>` and `x-api-key: <key>`. Leave it blank and no key
is added. It accepts a macro, so use `${env.*}`.

This is the key llama-swap presents *to* the peer. It is unrelated to the
`apiKeys` clients present *to* llama-swap.

## What ends up in your config file

Worth being aware of, because config files get pasted into issues and chats:

- `apiKeys` — literal keys, unless you used env macros
- `peers.*.apiKey` — literal peer keys, same
- `models.*.env` — literal `NAME=value` pairs
- `models.*.cmd` / `cmdStop` — full command lines, which often carry
  `--api-key` flags and absolute paths
- `macros` — **after** env substitution has already run

That last one is the non-obvious one: a macro like
`llama: "llama-server --api-key ${env.KEY}"` holds the resolved secret once the
config is loaded.

Before sharing a config, strip those. Redact rather than delete so the shape of
the problem survives.

## Related

- `reference/config/apiKeys`, `reference/config/peers`
- `guides/configuration/macros` — how env macros resolve
