import { describe, it, expect } from "vitest";
import { diffLines } from "../src/lib/textDiff";

describe("diffLines", () => {
  it("marks everything same when texts are identical", () => {
    const d = diffLines("a\nb\nc", "a\nb\nc");
    expect(d.every((l) => l.kind === "same")).toBe(true);
    expect(d.map((l) => l.text)).toEqual(["a", "b", "c"]);
  });

  it("detects an added line", () => {
    const d = diffLines("a\nb", "a\nb\nc");
    expect(d).toEqual([
      { kind: "same", text: "a" },
      { kind: "same", text: "b" },
      { kind: "added", text: "c" },
    ]);
  });

  it("detects a removed line", () => {
    const d = diffLines("a\nb\nc", "a\nc");
    expect(d).toEqual([
      { kind: "same", text: "a" },
      { kind: "removed", text: "b" },
      { kind: "same", text: "c" },
    ]);
  });

  it("detects a changed line as a removal + addition", () => {
    const d = diffLines("version: 1", "version: 2");
    expect(d).toEqual([
      { kind: "removed", text: "version: 1" },
      { kind: "added", text: "version: 2" },
    ]);
  });

  it("handles an empty old text (first-ever publish)", () => {
    const d = diffLines("", "a\nb");
    // "".split("\n") is [""] — a single empty line, itself a removal, plus the two real additions.
    expect(d).toEqual([
      { kind: "removed", text: "" },
      { kind: "added", text: "a" },
      { kind: "added", text: "b" },
    ]);
  });
});
