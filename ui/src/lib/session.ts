/**
 * Form login (security.auth.mode: form). The UI never handles the API key
 * itself: the login page at <prefix>/ui/login sets a session cookie, and the
 * browser attaches it to every same-origin fetch and EventSource the same way
 * it re-sent cached Basic credentials before.
 */
import { apiUrl } from "./apiPath";

/** Header llama-swap sets on the 401 a browser gets without a valid session. */
export const LOGIN_REQUIRED_HEADER = "X-Llama-Swap-Login";

/**
 * Reports whether a response means the form login session has ended. Only
 * llama-swap's own answer carries the marker header, so a 401 an upstream or
 * peer passes through (a bad peer key, say) is left to the page that made the
 * request. Basic mode never sets it either: the browser handles that itself.
 */
export function sessionEnded(res: Pick<Response, "status" | "headers">): boolean {
  return res.status === 401 && res.headers.get(LOGIN_REQUIRED_HEADER) === "required";
}

/** URL of the login page, returning to the current UI route afterwards. */
export function loginUrl(hash = ""): string {
  return apiUrl("/ui/login") + "?next=" + encodeURIComponent("/ui/") + hash;
}

let leaving = false;

/** Goes to the login page once, however many requests notice at the same time. */
function goToLogin(): void {
  if (leaving) return;
  leaving = true;
  window.location.assign(loginUrl(window.location.hash));
}

/**
 * Called when something fails in a way that does not show why, such as the
 * event stream dropping or a page's code failing to load. Ask the server
 * directly; a lapsed session goes to the login page.
 */
export async function checkSession(): Promise<void> {
  try {
    const res = await fetch(apiUrl("/api/version"));
    if (sessionEnded(res)) goToLogin();
  } catch {
    // The server is unreachable; the caller's own retry handles that.
  }
}

/**
 * Watches every request the UI makes and goes to the login page as soon as
 * one finds the session has ended, rather than leaving each page to show its
 * own error. Call once at startup.
 */
export function watchSession(): void {
  const fetchOriginal = window.fetch.bind(window);
  window.fetch = async (...args: Parameters<typeof fetch>) => {
    const res = await fetchOriginal(...args);
    if (sessionEnded(res)) goToLogin();
    return res;
  };
}

/** Ends the form login session and returns to the login page. */
export async function logout(): Promise<void> {
  try {
    await fetch(apiUrl("/ui/logout"), { method: "POST" });
  } finally {
    window.location.assign(apiUrl("/ui/login"));
  }
}
