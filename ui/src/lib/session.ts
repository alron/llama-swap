/**
 * Form login (security.auth.mode: form). The UI never handles the API key
 * itself: the login page at <prefix>/ui/login sets a session cookie, and the
 * browser attaches it to every same-origin fetch and EventSource the same way
 * it re-sent cached Basic credentials before.
 */
import { apiUrl } from "./apiPath";

/**
 * Reports whether a response means the form login session has ended. In form
 * mode the server answers a browser's request with a bare 401; the Basic
 * challenge (WWW-Authenticate) is only sent in basic mode, where the browser
 * shows its own dialog and the UI should stay out of the way.
 */
export function sessionEnded(res: Pick<Response, "status" | "headers">): boolean {
  return res.status === 401 && !res.headers.has("WWW-Authenticate");
}

/** URL of the login page, returning to the current UI route afterwards. */
export function loginUrl(hash = ""): string {
  return apiUrl("/ui/login") + "?next=" + encodeURIComponent("/ui/") + hash;
}

/**
 * Called when the event stream drops. An EventSource cannot see why it
 * failed, so ask the server directly; a lapsed session goes to the login page
 * rather than retrying forever behind a "disconnected" badge.
 */
export async function checkSession(): Promise<void> {
  try {
    const res = await fetch(apiUrl("/api/version"));
    if (sessionEnded(res)) {
      window.location.assign(loginUrl(window.location.hash));
    }
  } catch {
    // The server is unreachable; the stream's own retry handles that.
  }
}

/** Ends the form login session and returns to the login page. */
export async function logout(): Promise<void> {
  try {
    await fetch(apiUrl("/ui/logout"), { method: "POST" });
  } finally {
    window.location.assign(apiUrl("/ui/login"));
  }
}
