import { describe, it, expect } from "vitest";
import { sessionEnded, loginUrl } from "./session";

const res = (status: number, headers: Record<string, string> = {}) => ({ status, headers: new Headers(headers) });

describe("session", () => {
  it("treats a bare 401 as an ended form login session", () => {
    expect(sessionEnded(res(401))).toBe(true);
  });

  it("leaves a Basic challenge to the browser", () => {
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
});
