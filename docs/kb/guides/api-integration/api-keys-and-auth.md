---
title: API keys, access control, and keeping secrets out of your config
summary: apiKeys authentication has no per-key rate limits or user permissions; use env macros for secrets; security.auth.mode form gives browsers a login page.
category: guides
tags: [security, api-keys, auth, secrets, env, rate-limit, users, permissions, access-control, login, password-manager, session, cookie]
config_keys: [apiKeys, macros, peers.*.apiKey, models.*.env, security.auth.mode, security.auth.sessionTTL]
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
    mode: form        # default: basic
    sessionTTL: 604800 # seconds, default 7 days
```

Opening the UI now redirects to `/ui/login`. Enter one of the `apiKeys` as the
API key. A successful login sets a session cookie, and the sidebar gets a
logout button.

API clients are unaffected: `Authorization: Bearer`, `x-api-key` and Basic auth
keep working, and a request without a key from anything other than a browser
still gets the Basic challenge.

Things to know:

- **Form mode requires `apiKeys`.** Without a key the config fails to load.
- **Sessions survive restarts and config reloads.** To log every browser out,
  remove or rotate the key it logged in with; a config reload is enough.
  Logging out only clears that browser's cookie.
- **Instances on one host share a login when they share a key.** Cookies are
  per host, not per port or path, so llama-swap names the cookie after a
  fingerprint of the key. Instances with different keys keep separate logins.
- **The login does not stick over plain HTTP if the proxy says HTTPS.** The
  cookie is marked `Secure` when llama-swap serves TLS itself or a proxy sends
  `X-Forwarded-Proto: https`, and browsers then refuse to send it over plain
  HTTP.
- **Links from other sites work, embedding does not.** The session cookie only
  authenticates the UI's own requests and top-level page loads. A page on
  another site or port cannot use it to call the API, and the UI shown inside
  another site's frame asks for a login.

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
