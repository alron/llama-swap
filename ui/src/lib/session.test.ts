import { describe, it, expect, vi, afterEach } from "vitest";
import { sessionEnded, loginUrl, watchSession, LOGIN_REQUIRED_HEADER } from "./session";

const res = (status: number, headers: Record<string, string> = {}) => new Response(null, { status, headers });

describe("session", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("treats llama-swap's marked 401 as an ended session", () => {
    expect(sessionEnded(res(401, { [LOGIN_REQUIRED_HEADER]: "required" }))).toBe(true);
  });

  it("leaves a 401 passed through from an upstream or peer to the page", () => {
    expect(sessionEnded(res(401))).toBe(false);
    expect(sessionEnded(res(401, { "WWW-Authenticate": 'Basic realm="llama-swap"' }))).toBe(false);
  });

  it("ignores other statuses", () => {
    expect(sessionEnded(res(200))).toBe(false);
    expect(sessionEnded(res(403))).toBe(false);
    expect(sessionEnded(res(502))).toBe(false);
  });

  it("returns to the UI route after login", () => {
    // Vitest runs without a window, so apiUrl adds no prefix.
    expect(loginUrl()).toBe("/ui/login?next=%2Fui%2F");
    expect(loginUrl("#/models")).toBe("/ui/login?next=%2Fui%2F#/models");
  });

  it("goes to the login page once when any request finds the session ended", async () => {
    const responses = [
      res(200),
      res(401),
      res(401, { [LOGIN_REQUIRED_HEADER]: "required" }),
      res(401, { [LOGIN_REQUIRED_HEADER]: "required" }),
    ];
    const assign = vi.fn();
    vi.stubGlobal("window", {
      fetch: vi.fn(async () => responses.shift()!),
      location: { pathname: "/prefix/ui/", hash: "#/models", assign },
    });

    watchSession();
    expect((await window.fetch("/api/version")).status).toBe(200);
    expect((await window.fetch("/upstream/peer/v1/chat/completions")).status).toBe(401);
    expect(assign).not.toHaveBeenCalled();

    // The page still gets its response; the redirect happens alongside.
    expect((await window.fetch("/api/version")).status).toBe(401);
    expect((await window.fetch("/api/events")).status).toBe(401);
    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith("/prefix/ui/login?next=%2Fui%2F#/models");
  });
});
