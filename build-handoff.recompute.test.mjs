import assert from "node:assert/strict";
import test from "node:test";
import { buildStructuralHandoff } from "./build-handoff.mjs";

/*
 * THE ENVELOPE MUST CARRY EVERY INPUT THE SERVER RE-DERIVES THE GATE FROM.
 *
 * The control plane does not accept the CLI's pass/fail. It recomputes the gate from the sanitized
 * findings and the policy it was sent, compares that to the gate the artifact was signed with, and
 * REFUSES the whole upload when the two disagree — draft.ts's `if (gate.status !== expectedOverall
 * .status) return bad(...)`, surfaced as 400 INVALID_CI_HANDOFF.
 *
 * That makes the policy pick in build-handoff.mjs load-bearing in a way an allowlist does not look:
 * a field the server reads and the action omits does not degrade the result, it destroys the run.
 * `flaggedPaths` and `errorPaths` were both omitted, so both §4.3 flagged paths and the Ext-5
 * error-path rules recomputed as OFF. A customer using either knob saw their CI fail exactly as
 * configured, and then the upload refused with a bare "HTTP 400" — no evidence, no check run, no
 * dashboard row, and nothing anywhere saying which field was missing.
 *
 * `errorHandlers` is the other half of the Ext-5 rule and was never emitted at all. Sending the
 * policy without it is still broken: the server reads failOnUntested: true against a count of zero
 * and recomputes a pass. Both travel or neither helps, which is why they are asserted together.
 *
 * Adding an input to the server's recompute means adding it here in the same change.
 */

const SHA = "a".repeat(40);
const CTX = {
  repository: "acme/service",
  triggerSha: SHA,
  headSha: SHA,
  pullRequest: "42",
  workflowRef: `acme/service/.github/workflows/abloh.yml@${"c".repeat(40)}`,
  workflowSha: "c".repeat(40),
  runId: "777",
  runAttempt: "1",
  artifactDigest: `sha256:${"d".repeat(64)}`,
  policySource: "repository-file",
  policyPath: "abloh.yml",
  policyDigest: `sha256:${"f".repeat(64)}`,
};

/** An artifact from a run that used both opt-in gate rules. */
const evidence = () => ({
  schema: "attest-results/v2",
  engine: { name: "stryker", version: "8.0.0" },
  target: { baseSha: "b".repeat(40), sha: SHA, runner: "vitest" },
  scope: [],
  diffCoverage: null,
  rawCoverageDigest: null,
  rawCoverageFormat: null,
  redactedReportDigest: null,
  mutationExecution: null,
  mutationScope: [],
  tier: 1,
  mutantsPlanned: 10,
  mutantsRun: 10,
  counts: {
    killed: 9, timeout: 0, survived: 1, "no-coverage": 0,
    "runtime-error": 0, "build-error": 0, "skipped-by-cap": 0,
  },
  scores: {
    rawScore: 0.9, triagedScore: 0.9, denominator: 10,
    errorCount: 0, confirmedEquivalent: 0, triageValidated: false,
  },
  floor: null,
  /* Above threshold, and yet the CLI failed the run — because the one survivor sits under a
     flagged path. That is precisely the shape the server has to be able to reproduce. */
  gate: { status: "fail", score: 0.9, threshold: 0.7 },
  baseline: null,
  findings: [
    { file: "src/billing/charge.ts", startLine: 10, endLine: 10, status: "survived", mutator: "ConditionalExpression" },
  ],
  policy: {
    threshold: 0.7,
    enforce: true,
    tier: 1,
    floor: { minMutantsExecuted: 1, maxErrorRate: 0.1, minSamplingFraction: 0.5 },
    flaggedPaths: ["src/billing/"],
    errorPaths: { failOnUntested: true, failOnAntiPattern: false },
  },
  errorHandlers: {
    state: "completed",
    analyzerVersion: "1",
    untestedHandlerMutantCount: 2,
    antiPatternCountByKind: { "swallowed-exception": 1 },
  },
  rationalesDigest: "f".repeat(64),
  rawReportDigest: "f".repeat(64),
  skipBaseline: false,
});

test("the policy fields the server re-derives the gate from all reach the envelope", () => {
  const policy = buildStructuralHandoff(evidence(), CTX).evidence.policy;

  assert.deepEqual(
    policy.flaggedPaths,
    ["src/billing/"],
    "resolveFlaggedPaths reads this; without it flaggedPathViolationCount is 0 and the server " +
      "recomputes pass against a signed fail, refusing the upload with 400",
  );
  assert.deepEqual(
    policy.errorPaths,
    { failOnUntested: true, failOnAntiPattern: false },
    "the Ext-5 gate reads this; without it both rules default to off and the recompute disagrees",
  );
  /* Unchanged, and asserted so widening the pick cannot quietly drop one of the originals. */
  assert.equal(policy.threshold, 0.7);
  assert.equal(policy.enforce, true);
  assert.equal(policy.tier, 1);
});

test("the error-handler counts travel with the policy that switches them on", () => {
  /* Half a contract is still broken: with `errorPaths` present and `errorHandlers` absent the
     server reads failOnUntested against a count of zero, recomputes pass, and refuses. */
  const envelope = buildStructuralHandoff(evidence(), CTX);
  assert.ok(
    Object.hasOwn(envelope.evidence, "errorHandlers"),
    "errorHandlers must be emitted, or the error-path rule recomputes against zero",
  );
  assert.equal(envelope.evidence.errorHandlers.untestedHandlerMutantCount, 2);
  assert.equal(envelope.evidence.errorHandlers.state, "completed");
});

test("the fix loop's proofs digest travels, or its sidecar cannot be stored", () => {
  /* Third instance of one class in a single day: bytes forwarded with no commitment to check them
     against. patch-revert lost `reportDigest` to an allowlist, the redacted mutation report lost
     `redactedReportDigest` to never being emitted, and the fix loop lost the whole `fixLoop` block.
     Each was refused as sidecar.malformed with the run stored around the hole. */
  const withLoop = evidence();
  withLoop.fixLoop = {
    state: "completed",
    proven: 1,
    rejected: 0,
    omitted: 0,
    proofsDigest: "9".repeat(64),
    summaries: [{ mutantId: "src/a.ts:1:1:Foo", verdict: "proven" }],
  };
  const envelope = buildStructuralHandoff(withLoop, CTX, { fixProofs: "[]" });
  assert.equal(
    envelope.evidence.fixLoop?.proofsDigest,
    "9".repeat(64),
    "the tier-2 fix-proofs sidecar is verified against this; without it every proven test is refused",
  );
  assert.equal(envelope.evidence.fixLoop.proven, 1);
});

test("a failure reason cannot destroy the run it describes", () => {
  /*
   * OBSERVED, on the first run after `fixLoop` began travelling at all.
   *
   * The fix loop could not prepare its proof container, and its `reason` was written for a console:
   * the image reference, both remedies, and a tail of the customer's own vitest output — newlines,
   * an em dash, and vitest's `⎯` rule characters. The control plane accepts printable single-line
   * ASCII for that field and refuses the entire upload otherwise, so a complete and correct
   * measurement was discarded at ingest and the Action reported a bare "HTTP 400".
   *
   * The producer sends one scrubbed line now. This is the second guard, at the boundary, because
   * every producer of a `reason` is a failure path and the next one will be written for a console
   * too.
   */
  const withConsoleReason = evidence();
  withConsoleReason.fixLoop = {
    state: "unavailable",
    reason:
      "restricted-environment-unavailable: preflight suite was not green (exit 1) on Node v20.20.2 — " +
      "pin environment.runtimeImage\ntail:\n\u23AF\u23AF\u23AF Unhandled Error \u23AF\u23AF\u23AF\n" +
      "Error: ENOENT: no such file or directory, mkdir '/workspace/coverage'",
  };

  const reason = buildStructuralHandoff(withConsoleReason, CTX).evidence.fixLoop.reason;

  assert.doesNotMatch(reason, /[\r\n]/u, "a newline alone refuses the whole upload");
  assert.match(reason, /^[\x20-\x7e]*$/u, "and so does any character outside printable ASCII");
  assert.ok(reason.length <= 400, `bounded, got ${reason.length}`);
  /* The first line still says what happened — scrubbing must not leave an empty field. */
  assert.match(reason, /^restricted-environment-unavailable: /u);
  assert.ok(!reason.includes("mkdir"), "the suite tail belongs on stdout, not in an evidence field");
});

test("a reason that was already clean is untouched", () => {
  const clean = evidence();
  clean.fixLoop = { state: "not-run", reason: "no eligible real-gap survivors" };
  assert.equal(
    buildStructuralHandoff(clean, CTX).evidence.fixLoop.reason,
    "no eligible real-gap survivors",
  );
});

test("a run that configured neither rule sends null, and null recomputes as off", () => {
  /*
   * ABSENT IS NULL HERE, NOT A MISSING KEY — `field()` maps undefined to null on purpose, so
   * JSON.stringify cannot drop it and a receiver can tell "the producer sent nothing" apart from
   * "the producer has never heard of this". The two bugs that convention exists to prevent are the
   * same two this test file is about.
   *
   * Null must therefore recompute as OFF on the server, which is what both readers already do:
   * resolveFlaggedPaths asks Array.isArray (false for null, so no flagged paths), and the Ext-5
   * gate reads `policy?.errorPaths?.failOnUntested === true` (undefined for null, so false). A run
   * that configured neither rule gets the same gate it always did.
   */
  const bare = evidence();
  delete bare.policy.flaggedPaths;
  delete bare.policy.errorPaths;
  bare.errorHandlers = null;

  const envelope = buildStructuralHandoff(bare, CTX);
  assert.equal(envelope.evidence.policy.flaggedPaths, null);
  assert.equal(envelope.evidence.policy.errorPaths, null);
  assert.equal(envelope.evidence.errorHandlers, null);
  assert.equal(envelope.evidence.fixLoop, null);

  /* And the keys survive serialization, which is the only form the server ever sees. */
  const wire = JSON.parse(JSON.stringify(envelope));
  assert.ok(Object.hasOwn(wire.evidence.policy, "flaggedPaths"));
  assert.ok(Object.hasOwn(wire.evidence.policy, "errorPaths"));
});
