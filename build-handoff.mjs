#!/usr/bin/env node
/**
 * Builds the `abloh-ci-handoff/v2` envelope that the authenticated control-plane
 * endpoint accepts.
 *
 * This replaces a ~240-line jq filter that lived inside the workflow YAML. The jq
 * version could not be unit tested, which is how the producer and the validator in
 * that same file drifted apart on `baseline` keys without anyone noticing.
 *
 * CONTRACT: the output must remain byte-identical to the jq filter's output.
 * `build-handoff.differential.test.mjs` enforces that against every corpus
 * artifact by running both and comparing the serialized result. Two consequences
 * for anyone editing this file:
 *
 *   1. Key insertion order is part of the contract. jq emits object keys in the
 *      order the filter constructs them and this file mirrors that order exactly.
 *      Reordering a property is a behavioural change.
 *   2. jq's `//` is an ALTERNATIVE operator, not a null-coalesce: `a // b` yields
 *      `b` when `a` is null OR false. `alt()` below reproduces that, and it is
 *      deliberately not `??`.
 *
 * This is the ONLY upload builder. The endpoint it feeds derives repository
 * identity from GitHub's signed OIDC token rather than trusting the payload, so
 * no field here may carry a runner-local path.
 */

import { readFileSync, realpathSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** jq's `//`. Falls through on null AND false, unlike `??`. */
function alt(value, fallback) {
  return value === null || value === undefined || value === false ? fallback : value;
}

/**
 * jq's `.foo` on a key the object does not have yields `null`. JavaScript yields
 * `undefined`, and JSON.stringify DELETES undefined-valued keys — so a field the
 * producer happened to omit would vanish from the envelope entirely and the
 * endpoint's exact-key checks would reject the whole upload.
 *
 * Every fixed-shape object is therefore built from an explicit key list rather
 * than by spreading or by property-by-property copying: the key list is the
 * schema, absences become null, and unknown producer keys cannot leak through.
 * Key order follows the array, which is part of the output contract.
 */
function field(value) {
  return value === undefined ? null : value;
}

/** First line, printable ASCII, bounded — the shape the control plane accepts for a reason. */
function printableLine(value, max = 400) {
  const firstLine = String(value).split(/\r?\n/u)[0] ?? "";
  const ascii = firstLine.replace(/[^\x20-\x7e]/gu, "?").trim();
  return ascii.length <= max ? ascii : ascii.slice(0, max);
}

function pick(source, keys) {
  const from = source ?? {};
  const out = {};
  for (const key of keys) out[key] = field(from[key]);
  return out;
}

/**
 * The closed vocabulary of Layer-0 cannot-attest reasons.
 *
 * Provider diagnostics are free text and can embed local paths and parser
 * excerpts, so the raw value is never carried. It is mapped to one of nine codes
 * and an unrecognized reason is a hard failure — silently forwarding it is how a
 * path would escape.
 */
const L0_REASON_CODES = new Set([
  "coverage-provider-unavailable",
  "coverage-provider-version-mismatch",
  "coverage-run-failed",
  "coverage-report-missing",
  "coverage-report-invalid",
  "coverage-scope-invalid",
  "coverage-scope-incomplete",
  "coverage-py-unavailable",
  "coverage-acquisition-failed",
]);

const RUNNER_NO_PROVIDER =
  /^(jest|vitest|mocha|node-test|ava|tap|jasmine|bun|pytest) runner: no Layer 0 coverage provider$/;
const COVERAGE_OMITS_SCOPED = /^coverage report omits [1-9][0-9]* scoped file\(s\)$/;

export function normalizeL0Reason(reason) {
  if (typeof reason !== "string") {
    throw new Error("diff coverage cannot-attest reason is required");
  }
  if (L0_REASON_CODES.has(reason)) return reason;
  if (reason === "coverage.py is not installed in the project's interpreter") {
    return "coverage-py-unavailable";
  }
  if (reason === "coverage provider version mismatch") {
    return "coverage-provider-version-mismatch";
  }
  if (
    reason === "coverage provider unavailable" ||
    reason === "bundled coverage provider unavailable" ||
    reason === "coverage unavailable" ||
    RUNNER_NO_PROVIDER.test(reason)
  ) {
    return "coverage-provider-unavailable";
  }
  if (reason === "coverage run exited nonzero (untrusted)") return "coverage-run-failed";
  if (reason === "coverage report not produced" || reason === "coverage report was not produced") {
    return "coverage-report-missing";
  }
  if (
    reason === "changed-file path cannot be represented by the coverage include filter" ||
    reason === "empty scope"
  ) {
    return "coverage-scope-invalid";
  }
  if (
    reason === "a requested changed file is missing from the coverage report" ||
    COVERAGE_OMITS_SCOPED.test(reason)
  ) {
    return "coverage-scope-incomplete";
  }
  if (
    reason === "coverage json failed" ||
    reason.startsWith("coverage report ") ||
    reason.startsWith("lcov ")
  ) {
    return "coverage-report-invalid";
  }
  if (reason === "coverage acquisition failed") return "coverage-acquisition-failed";
  throw new Error("diff coverage cannot-attest reason is not recognized");
}

/** `{file, ranges, lines}` only — drops any other key the producer may add. */
function scopeEntries(entries) {
  return (alt(entries, [])).map((entry) => ({
    file: entry.file,
    ranges: entry.ranges.map((range) => [range[0], range[1]]),
    lines: entry.lines,
  }));
}

const PROVIDER_KEYS = ["runner", "provider", "runnerVersion", "providerVersion"];
const COVERAGE_COUNT_KEYS = ["changed", "covered", "uncovered", "notInstrumented"];
const COUNT_KEYS = [
  "killed", "timeout", "survived", "no-coverage",
  "runtime-error", "build-error", "skipped-by-cap",
];
const SCORE_KEYS = [
  "rawScore", "triagedScore", "denominator",
  "errorCount", "confirmedEquivalent", "triageValidated",
];
const FLOOR_KEYS = ["minMutantsExecuted", "maxErrorRate", "minSamplingFraction"];
const BASELINE_KEYS = [
  "runs", "durationsMs", "redBaseline", "testCount", "testCounts",
  "testIdentityCount", "ambiguousIdentityCount", "flakyCount",
  "timingCv", "timeoutFactor", "quarantineDowngraded",
];
const FINDING_KEYS = [
  "mutantId", "file", "startLine", "endLine", "mutator", "status", "coveredBy",
];
/*
 * What TIER 2 additionally sends, and nothing beyond it.
 *
 * The mutated span's exact columns, the source slice that was there (`originalText`) and the slice
 * that replaced it. `originalText` IS CUSTOMER SOURCE, which is why this list is reached only when the
 * artifact itself reports tier 2 — the customer's explicit choice to let Abloh hold the evidence
 * rather than only its shape.
 *
 * IT MUST MATCH THE SERVER. `TIER2_ADDITIONAL_FINDING_FIELDS` in apps/api/src/draft.ts is the same
 * four names. Widening one side alone is silent: a field this strips never reaches the server's
 * allowlist to be kept, and a field the server drops was uploaded for nothing. Both were the same
 * seven structural names until tier 2 existed, which is exactly how they drifted unnoticed.
 */
const TIER2_FINDING_KEYS = [
  "originalText", "replacement", "startColumn", "endColumn",
];
/*
 * The triage fields that travel.
 *
 * modelId, promptVersion and effort are the CLASSIFIER IDENTITY, and they are safe to send
 * because a project cannot choose them: a committed policy file may not name a model, so these
 * always identify the service's own classifier and never anything the customer wrote.
 *
 * They matter for two things that are impossible without them. A run can only be marked
 * triage-validated by matching an exact (model, prompt, effort) triple, so a run that omits them
 * can never be validated. And a human label on a verdict is meaningless unless it can be
 * attributed to whatever produced that verdict — the moment the prompt changes, unattributed
 * labels become noise.
 */
const TRIAGE_KEYS = [
  "verdict",
  "reasonCode",
  "confidence",
  "overridden",
  "description",
  "impact",
  "modelId",
  "promptVersion",
  "effort",
];

/**
 * Layer 0. A completed measurement (or a not-applicable one with no executable
 * lines) carries its per-line classification; every other state carries the
 * state, a normalized reason and nothing else — counts and lines would be
 * unfounded.
 */
/** Closed per-package row keys (counts-only rows; the server re-derives every quantity). */
const PACKAGE_ROW_KEYS = [
  "directory",
  "runner",
  "diffCoverage",
  "mutation",
  "baseline",
  "environmentContractDigest",
  "reachedStage",
];

/**
 * Closed reverse-patch block keys. `gapLocations` is projected separately because it is an array
 * of objects and `pick` copies values verbatim.
 */
const PATCH_REVERT_BLOCK_KEYS = [
  "state",
  "reason",
  "status",
  "gaps",
  /* The denominator. Its absence was not cosmetic: the control plane REQUIRES it on a completed
     block, so every reverse-patch run uploaded through this action was refused with a 400 while
     the same run uploaded directly was accepted. */
  "regionsChecked",
  "fullSuiteRuns",
  "impactScreenRuns",
  "addedWallMs",
  "suiteEquivalents",
  /* THE SIDECAR'S OWN COMMITMENT.
     The CLI stamps this over the exact bytes it wrote to attest-patch-revert.json, and the action
     forwards those bytes verbatim below. Dropping it here meant the control plane received a
     document it had no way to check, which acceptPatchRevertSidecar refuses by design — "no
     commitment, no storage" — so every reverse-patch report was uploaded and then discarded as
     malformed. Same failure as `regionsChecked` above: an allowlist that fell behind the producer. */
  "reportDigest",
];

/**
 * Closed reverse-patch gap-row keys.
 *
 * A location and nothing else. The reverted source and the identities of the tests involved stay
 * in the customer's local sidecar, so an allowlist here is what makes that boundary structural
 * rather than a promise — a producer that started attaching source could not leak it through.
 */
const PATCH_REVERT_GAP_KEYS = ["path", "startLine", "endLine", "unitKind", "symbol", "untested"];

function diffCoverageBlock(dc) {
  if (dc === null || dc === undefined) return null;
  const measured =
    dc.state === "completed" ||
    (dc.state === "not-applicable" && dc.reason === "no-executable-lines");

  if (measured) {
    return {
      state: dc.state,
      reason: alt(dc.reason, null),
      wallMs: dc.wallMs,
      provider: pick(dc.provider, PROVIDER_KEYS),
      counts: {
        ...pick(dc.counts, COVERAGE_COUNT_KEYS),
        /* Older producers omit this; jq's `// 0` made it zero, not null. */
        notExecutable: alt(dc.counts?.notExecutable, 0),
      },
      /* Retry-once disclosure — was silently dropped by this projection (WS3 fold). */
      acquisitionAttempts: alt(dc.acquisitionAttempts, null),
      lines: dc.lines.map((line) => ({ file: line.file, line: line.line, state: line.state })),
    };
  }

  return {
    state: dc.state,
    reason: dc.state === "cannot-attest" ? normalizeL0Reason(dc.reason) : dc.reason,
    wallMs: alt(dc.wallMs, null),
    provider: dc.provider === null || dc.provider === undefined ? null : pick(dc.provider, PROVIDER_KEYS),
    counts: null,
    acquisitionAttempts: alt(dc.acquisitionAttempts, null),
    lines: [],
  };
}

/** Baseline durations and per-run test totals are capped at the first 10 runs. */
function baselineBlock(baseline) {
  if (baseline === null || baseline === undefined) return null;
  return {
    ...pick(baseline, BASELINE_KEYS),
    /* Both arrays are capped at the first 10 runs. */
    durationsMs: alt(baseline.durationsMs, []).slice(0, 10),
    testCounts: alt(baseline.testCounts, []).slice(0, 10),
  };
}

/**
 * Findings are allowlist-copied. `replacement`, `originalText` and the triage
 * rationale are source-bearing and are dropped by omission here.
 */
function findingEntries(findings, tier) {
  const keys = tier === 2 ? [...FINDING_KEYS, ...TIER2_FINDING_KEYS] : FINDING_KEYS;
  return alt(findings, [])
    .slice(0, 10_000)
    .map((finding) => ({
      ...pick(finding, keys),
      triage:
        finding.triage === null || finding.triage === undefined
          ? null
          : pick(finding.triage, TRIAGE_KEYS),
    }));
}

/**
 * @param {object} evidence  parsed attest-results.json from the runner
 * @param {object} ctx       GitHub-supplied provenance and policy identity
 * @param {{rationales?: string, fixProofs?: string, patchRevert?: string, coverage?: string}} [sidecars]
 *   Uploaded sidecars, as the RAW BYTES of the local files.
 *
 *   `rationales` and `fixProofs` are TIER-2 ONLY — they carry model prose and generated test bodies,
 *   so they are omitted entirely below tier 2 and for any run that produced neither.
 *
 *   `patchRevert` and `coverage` travel at EVERY tier. Both are structural: unit ids, digests,
 *   counts and outcomes in one; line and column maps with hit counters in the other. Neither carries
 *   source text, so gating them by tier would withhold evidence without protecting anything.
 *
 *   Passed as a separate argument, and the key omitted when absent, so that every existing two-argument
 *   call produces byte-identical output — which is what keeps the differential contract against the
 *   retired jq filter meaningful instead of merely re-baselined.
 *
 *   The bytes are forwarded UNCHANGED. The control plane verifies them against `rationalesDigest`,
 *   `fixLoop.proofsDigest` and `patchRevert.reportDigest`, which the evidence block already carries,
 *   so re-serializing here would break the verification that makes these files evidence rather than
 *   attachments.
 */
export function buildStructuralHandoff(evidence, ctx, sidecars) {
  return {
    schema: "abloh-ci-handoff/v2",
    provenance: {
      repository: ctx.repository,
      triggerSha: ctx.triggerSha,
      headSha: ctx.headSha,
      /* Empty string means "not a pull request", not "PR zero". */
      pullRequest: ctx.pullRequest === "" ? null : Number(ctx.pullRequest),
      workflowRef: ctx.workflowRef,
      workflowSha: ctx.workflowSha,
      githubRunId: ctx.runId,
      githubRunAttempt: ctx.runAttempt,
    },
    artifactDigest: ctx.artifactDigest,
    evidence: {
      schema: field(evidence.schema),
      engine: pick(evidence.engine, ["name", "version"]),
      /* target.repo is deliberately absent: on the runner it is a local
         filesystem path. Repository identity comes from the OIDC claim. */
      target: pick(evidence.target, ["baseSha", "sha", "runner"]),
      scope: scopeEntries(evidence.scope),
      diffCoverage: diffCoverageBlock(evidence.diffCoverage),
      rawCoverageDigest: field(evidence.rawCoverageDigest),
      rawCoverageFormat: field(evidence.rawCoverageFormat),
      /*
       * The fix-loop block, and with it `proofsDigest`.
       *
       * The Action already uploads `attest-fix-proofs.json` at tier 2 (sidecars.fixProofs below),
       * and the control plane will only store bytes it can check against a commitment. That
       * commitment is `fixLoop.proofsDigest`, and this block was never emitted — so every proven
       * test a customer's fix loop generated was uploaded, refused as `sidecar.malformed`, and lost.
       * The generated test bodies stay in the sidecar; what travels here is counts, verdicts and
       * digests, which is why it rides at every tier.
       */
      fixLoop:
        evidence.fixLoop === null || evidence.fixLoop === undefined
          ? null
          : {
              ...evidence.fixLoop,
              /*
               * A DIAGNOSTIC MUST NOT BE ABLE TO DESTROY THE RUN IT DESCRIBES.
               *
               * The control plane requires printable single-line ASCII here and refuses the whole
               * upload otherwise. `reason` is produced by failure paths — an unavailable proof
               * environment, an exceeded budget — and one of them interpolated the customer's own
               * suite tail, complete with newlines and vitest's `⎯` rule characters. The
               * measurement was finished and correct; the evidence was thrown away at ingest and
               * the Action reported a bare "HTTP 400".
               *
               * The producer now sends one scrubbed line, and this is the second guard: the field
               * is normalised at the boundary as well, so no future failure message can reach the
               * receiver in a shape it refuses.
               */
              ...(typeof evidence.fixLoop.reason === "string"
                ? { reason: printableLine(evidence.fixLoop.reason) }
                : {}),
            },
      /* The changed-error-handler analysis. Half of the Ext-5 recompute: `policy.errorPaths` above
         says whether the rule is on, and this says how many untested handler mutants and
         anti-patterns it found. With the policy alone the server reads failOnUntested: true against
         a count of zero and still recomputes a pass, so both must travel or neither helps. Null when
         no scan ran. */
      errorHandlers:
        evidence.errorHandlers === null || evidence.errorHandlers === undefined
          ? null
          : evidence.errorHandlers,
      /* The REDACTED mutation report's commitment, for exactly the reason above.
         `mutationRedacted` is forwarded in `sidecars` and the control plane checks it against this
         value; the field was never emitted, so those bytes always arrived uncheckable and were
         refused. The digest describes the source-free rewrite, not `rawReportDigest`'s verbatim
         report, which never leaves the runner. */
      redactedReportDigest: field(evidence.redactedReportDigest),
      mutationExecution:
        evidence.mutationExecution === null || evidence.mutationExecution === undefined
          ? null
          : {
              state: evidence.mutationExecution.state,
              reason: alt(evidence.mutationExecution.reason, null),
              scope: alt(evidence.mutationExecution.scope, null),
            },
      mutationScope: scopeEntries(evidence.mutationScope),
      /* Per-phase wall clock. The run page states what each stage cost, and a duration that does
         not survive this boundary is a duration the hosted UI can never show. */
      mutationWallMs: field(evidence.mutationWallMs),
      triageWallMs: field(evidence.triageWallMs),
      tier: field(evidence.tier),
      mutantsPlanned: field(evidence.mutantsPlanned),
      mutantsRun: field(evidence.mutantsRun),
      counts: pick(evidence.counts, COUNT_KEYS),
      scores: pick(evidence.scores, SCORE_KEYS),
      floor:
        evidence.floor === null || evidence.floor === undefined
          ? null
          : pick(evidence.floor, [...FLOOR_KEYS, "passed"]),
      gate: pick(evidence.gate, ["status", "score", "threshold"]),
      baseline: baselineBlock(evidence.baseline),
      /* The TRUE total, deliberately not findings.length: the array above is
         capped at 10000 so a consumer can tell truncation happened. */
      findingCount: alt(evidence.findings, []).length,
      findings: findingEntries(evidence.findings, evidence.tier),
      policy: {
        /*
         * THE FIELDS THE SERVER RECOMPUTES THE GATE FROM.
         *
         * The control plane does not trust the CLI's pass/fail: it re-derives the gate from the
         * sanitized findings and this policy, then REFUSES the upload when its answer differs from
         * the one the artifact was signed with (draft.ts:3366 -> 400 INVALID_CI_HANDOFF).
         *
         * `flaggedPaths` and `errorPaths` are inputs to that recompute — resolveFlaggedPaths and the
         * Ext-5 error-path gate read them. Omitting them made the server default both rules to OFF,
         * so a run the CLI failed under either rule recomputed as passing and the whole upload was
         * rejected. The customer's CI failed as configured, then the evidence, check run and
         * dashboard row never existed, and the Action reported only "HTTP 400" with no body.
         *
         * Anything added to the server's recompute must be added here in the same change.
         */
        ...pick(evidence.policy, ["threshold", "enforce", "tier", "flaggedPaths", "errorPaths"]),
        policyDigest: ctx.policyDigest === "" ? null : ctx.policyDigest,
        source: {
          kind: ctx.policySource,
          path: ctx.policyPath === "" ? null : ctx.policyPath,
          /* The policy is read at the measured commit, so its source sha is the
             head sha; the validator asserts these are equal. */
          sourceSha: ctx.headSha,
        },
        floor: pick(evidence.policy?.floor, FLOOR_KEYS),
      },
      rationalesDigest: field(evidence.rationalesDigest),
      rawReportDigest: field(evidence.rawReportDigest),
      skipBaseline: field(evidence.skipBaseline),
      /* WS3 widened shape: the worst-of compat signal, per-package rows (counts only by
         construction), and the bounded mutant roster the server derives per-package kills
         from. Null when absent — the server treats null as absent. */
      evidenceProfile: evidence.evidenceProfile === null || evidence.evidenceProfile === undefined
        ? null
        : evidence.evidenceProfile,
      packages: Array.isArray(evidence.packages)
        ? evidence.packages.slice(0, 8).map((row) => pick(row, PACKAGE_ROW_KEYS))
        : null,
      mutantRoster: Array.isArray(evidence.mutantRoster)
        ? evidence.mutantRoster.slice(0, 20000).map((entry) => ({ file: entry.file, status: entry.status }))
        : null,
      /* Reverse-patch verification (opt-in beta): an advisory block carrying its verdict, its
         cost in suite-equivalents, and bounded gap LOCATIONS. Null when absent. It never reaches
         a score, a floor or a gate on either side of the wire. */
      patchRevert:
        evidence.patchRevert === null || evidence.patchRevert === undefined
          ? null
          : {
              ...pick(evidence.patchRevert, PATCH_REVERT_BLOCK_KEYS),
              gapLocations: Array.isArray(evidence.patchRevert.gapLocations)
                ? evidence.patchRevert.gapLocations.slice(0, 64).map((gap) => pick(gap, PATCH_REVERT_GAP_KEYS))
                : null,
            },
      /* The discovery receipt: the runner's discovered test FILE PATHS, and only the paths
         (Kenneth's 2026-08-10 decision — paths may egress at tier >= 1; names, titles and source
         never do). Copied by closed key — `files` and nothing beside it — and deliberately NOT
         sliced or repaired here: the control plane re-validates the whole block and refuses it
         WHOLE on any violation, so a trim on this side would turn a block the server must refuse
         into one it accepts. Null when the run made no discovery claim. The TIER GATE lives on
         the server (acceptTestDiscovery): the block travels at every tier so the tier-0 strip is
         DISCLOSED in the stored egress audit rather than silently pre-empted on the runner. */
      testDiscovery:
        evidence.testDiscovery === null || evidence.testDiscovery === undefined
          ? null
          : { files: field(evidence.testDiscovery.files) },
    },
    /* Only what exists. An absent key is the ordinary case, which is why this is spread last rather
       than emitted as null: the receiver's key check treats it as optional, and a null would be a
       claim that the run had sidecars and they were empty. */
    ...(() => {
      const payload = sidecarPayload(sidecars, evidence.tier);
      return payload === null ? {} : { sidecars: payload };
    })(),
  };
}

/**
 * The sidecar bytes actually present, or null when there is nothing to send.
 *
 * The tier gate lives HERE rather than around the whole key, because the three sidecars do not
 * disclose the same thing. Rationales are model prose and fix proofs are generated test bodies, so
 * both are the customer's tier-2 decision. The reverse-patch report is unit ids, digests, counts and
 * outcomes — nothing a tier-0 run withholds — so gating it by tier would suppress evidence without
 * protecting anything.
 *
 * `patchRevert` is appended last so a run that produces none emits byte-identical output to before
 * it existed, which is what keeps the differential contract meaningful rather than re-baselined.
 */
function sidecarPayload(sidecars, tier) {
  if (sidecars === null || sidecars === undefined) return null;
  const payload = {};
  if (tier === 2) {
    if (typeof sidecars.rationales === "string" && sidecars.rationales.length > 0) {
      payload.rationales = sidecars.rationales;
    }
    if (typeof sidecars.fixProofs === "string" && sidecars.fixProofs.length > 0) {
      payload.fixProofs = sidecars.fixProofs;
    }
  }
  if (typeof sidecars.patchRevert === "string" && sidecars.patchRevert.length > 0) {
    payload.patchRevert = sidecars.patchRevert;
  }
  if (typeof sidecars.coverage === "string" && sidecars.coverage.length > 0) {
    payload.coverage = sidecars.coverage;
  }
  /* Tier 1 and above. Per-mutant lines and mutators are more than the tier-0 promise allows to
     leave a customer's CI, and the control plane refuses this key for a tier-0 run regardless —
     the gate is repeated there because this file runs on the customer's own machine. */
  if (tier >= 1 && typeof sidecars.mutationRedacted === "string" && sidecars.mutationRedacted.length > 0) {
    payload.mutationRedacted = sidecars.mutationRedacted;
  }
  return Object.keys(payload).length > 0 ? payload : null;
}

export function contextFromEnvironment(environment = process.env) {
  return {
    repository: environment.GITHUB_REPOSITORY ?? "",
    triggerSha: environment.ABLOH_TRIGGER_SHA ?? "",
    headSha: environment.ABLOH_HEAD_SHA ?? "",
    pullRequest: environment.ABLOH_PULL_REQUEST ?? "",
    workflowRef: environment.GITHUB_WORKFLOW_REF ?? "",
    workflowSha: environment.GITHUB_WORKFLOW_SHA ?? "",
    runId: environment.GITHUB_RUN_ID ?? "",
    runAttempt: environment.GITHUB_RUN_ATTEMPT ?? "",
    artifactDigest: environment.ABLOH_LOCAL_ARTIFACT_DIGEST ?? "",
    policySource: environment.ABLOH_POLICY_SOURCE ?? "",
    policyPath: environment.ABLOH_POLICY_PATH ?? "",
    policyDigest: environment.ABLOH_POLICY_DIGEST ?? "",
  };
}

/**
 * One tier-2 sidecar, read as RAW BYTES.
 *
 * Not parsed and re-serialized: the control plane checks these against a digest the evidence block
 * already declared, and any re-encoding — even a semantically identical one — would change the bytes
 * and fail that check. A missing file is the ordinary case and yields undefined, not an error: most
 * runs have no fix proofs, and a tier-2 run with no triage has no rationales either.
 *
 * The cap is the same 16 MiB the evidence file gets. It exists so a pathological sidecar cannot make
 * the runner read an unbounded file into memory before the server ever sees it.
 */
function readSidecar(path) {
  if (!path) return undefined;
  try {
    const bytes = statSync(path).size;
    if (bytes < 1 || bytes > 16 * 1024 * 1024) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

function main() {
  const evidencePath = process.env.ABLOH_EVIDENCE_PATH;
  if (!evidencePath) throw new Error("ABLOH_EVIDENCE_PATH is required");
  const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
  /* Handed in unconditionally; buildStructuralHandoff drops them below tier 2, so the tier decision
     lives in one place rather than being re-derived here. */
  const sidecars = {
    rationales: readSidecar(process.env.ABLOH_RATIONALES_PATH),
    fixProofs: readSidecar(process.env.ABLOH_FIX_PROOFS_PATH),
  };
  process.stdout.write(
    JSON.stringify(buildStructuralHandoff(evidence, contextFromEnvironment(), sidecars)),
  );
}

/*
 * Run as a script, stay silent when imported.
 *
 * Two traps here, both of which produce an EMPTY envelope rather than an error:
 *
 *  - The workflow pipes this file to `node --input-type=module` on STDIN, where
 *    process.argv[1] is undefined. Any comparison against it fails, main() never
 *    runs, and the upload step writes a zero-byte payload.
 *  - argv[1] is the path as given, while import.meta.url is fully resolved. On
 *    macOS /var is a symlink to /private/var, so the two disagree for the same
 *    file. Both sides are therefore reduced to a real path before comparison.
 */
function isEntryPoint() {
  const entry = process.argv[1];
  if (!entry) return true; /* stdin: nothing else could have imported us */
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) main();
