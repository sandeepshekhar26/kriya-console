// A small, dependency-free line-diff (LCS-based) for the Policy authoring "preview diff vs latest"
// step (doc 22 §5, P3) — these are short, hand-authored config blobs (policy YAML/JSON, a handful of
// govern[] directives), never a reason to pull in a diff library for this one view.

export type DiffLine = { kind: "same" | "added" | "removed"; text: string };

/** Longest-common-subsequence line diff — a standard O(n·m) table, fine for the short texts this view
 *  ever diffs (a policy draft is at most a few dozen lines). */
export function diffLines(oldText: string, newText: string): DiffLine[] {
  const a = oldText.split("\n");
  const b = newText.split("\n");
  const n = a.length;
  const m = b.length;

  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i]! });
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ kind: "removed", text: a[i]! });
      i++;
    } else {
      out.push({ kind: "added", text: b[j]! });
      j++;
    }
  }
  while (i < n) {
    out.push({ kind: "removed", text: a[i]! });
    i++;
  }
  while (j < m) {
    out.push({ kind: "added", text: b[j]! });
    j++;
  }
  return out;
}
