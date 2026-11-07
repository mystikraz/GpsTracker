import { beforeEach, describe, expect, it } from "vitest";
import { readAndClearFragmentToken } from "./api";

describe("fragment token handling", () => {
  beforeEach(() => window.history.replaceState(null, "", "/reset-password#one-time-token"));

  it("returns and clears the one-time token", () => {
    expect(readAndClearFragmentToken()).toBe("one-time-token");
    expect(window.location.hash).toBe("");
    expect(window.location.pathname).toBe("/reset-password");
  });
});
