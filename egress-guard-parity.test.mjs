import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

/*
 * The description egress guard exists SIX times, and it has to. The runner cannot import
 * @abloh/core (it is a standalone script with no workspace resolution), the workflow template
 * runs on the customer's checkout with no copy of this repository at all, and the GitHub app is
 * deliberately dependency-free. So the same predicate is written out once per trust boundary.
 *
 * Six copies of one rule is the exact condition that has already cost this product twice:
 * a producer and a validator disagreeing, silently, with no signal at either end. And this
 * particular guard fails QUIETLY — a refused sentence is replaced by the generic template and
 * nothing logs, so a mirror that drifts looks like model variance rather than a bug. It took a
 * live instrumented triage run to find the last one.
 *
 * This file pins them to each other.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

/**
 * An apostrophe doing English work — possession or contraction — elided before the quote
 * check, so "the parser's guard" is not read as a quoted identifier. Every copy must carry
 * this verbatim.
 */
const ELISION = String.raw`(?<=[A-Za-z])'(?=[A-Za-z])|(?<=s)'(?![A-Za-z])`;

/** Copies that PRODUCE a sentence: they fold smart punctuation to ASCII before checking. */
const PRODUCERS = ["packages/core/src/findings.ts", "apps/action/prepare-upload.mjs"];

/**
 * Copies that VALIDATE one. They sit downstream of a producer, so the text has already been
 * folded and the ASCII rule stays strict here — a non-ASCII description arriving at one of
 * these means something other than our pipeline wrote it, and refusing is correct.
 */
const VALIDATORS = [
  "apps/api/src/draft.ts",
  "apps/github-app/src/annotations.ts",
  "apps/github-app/src/server.ts",
];

/**
 * The smart-punctuation folds a producer must apply, matched as the ESCAPE SEQUENCES the
 * source actually spells them with — a fold table written in literal characters would be
 * unreadable in a diff and invisible in a review.
 */
const FOLDS = [
  String.raw`\u2010-\u2015`, // hyphen, en dash, em dash, horizontal bar
  String.raw`\u2018\u2019`, // single curly quotes
  String.raw`\u201C-\u201F`, // double curly quotes
  String.raw`\u2026`, // ellipsis
];

const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

test("every copy of the guard elides English apostrophes", () => {
  /* The producer now emits possessives. A validator that still refused them would break the
     pipeline precisely at that boundary, and break it invisibly. */
  for (const rel of [...PRODUCERS, ...VALIDATORS]) {
    assert.ok(
      read(rel).includes(ELISION),
      `${rel} does not carry the apostrophe elision — it will refuse "the parser's guard"`,
    );
  }
});

test("every producer folds smart punctuation before the ASCII check", () => {
  /* Models emit em dashes, curly quotes and ellipses constantly. Folding keeps the sentence;
     the ASCII rule that follows still stops homoglyphs and direction overrides. */
  for (const rel of PRODUCERS) {
    const source = read(rel);
    for (const fold of FOLDS) {
      assert.ok(source.includes(fold), `${rel} does not fold ${fold} — clean sentences are refused`);
    }
  }
});

test("no seventh copy has appeared without the elision", () => {
  /*
   * The check that actually holds the line: a new guard written next year, in a file nobody
   * listed above, is caught here rather than in production. A description quote-check must
   * test the ELIDED text, never the raw text.
   */
  const offenders = [];
  for (const file of sourceFiles(ROOT)) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/\/\["']\/u\.test\(([^\n]*)/g)) {
      if (!match[1].includes(".replace(")) {
        offenders.push(`${relative(ROOT, file)}: ${match[0].trim().slice(0, 80)}`);
      }
    }
  }
  assert.deepEqual(offenders, [], "these refuse possessives — elide the English apostrophes first");
});

/** Every source file in the workspace, skipping build output and dependencies. */
function sourceFiles(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".next" || entry.startsWith(".git")) {
      continue;
    }
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) sourceFiles(path, out);
    else if (/\.(ts|tsx|mjs|js|yml)$/.test(entry)) out.push(path);
  }
  return out;
}
