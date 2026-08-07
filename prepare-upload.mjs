#!/usr/bin/env node

import { readFileSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_SCOPE_LINES = 200_000;
const MAX_FINDINGS = 10_000;
const RAW_COVERAGE_FORMATS = [
  "istanbul-coverage-final-v1",
  "lcov-v1",
  "coverage-py-json-v1",
];
const COVERAGE_PROVIDER_MATRIX = Object.freeze({
  jest: Object.freeze(["v8", "babel"]),
  vitest: Object.freeze(["v8"]),
  mocha: Object.freeze(["c8"]),
  "node-test": Object.freeze(["c8"]),
  ava: Object.freeze(["c8"]),
  tap: Object.freeze(["c8"]),
  jasmine: Object.freeze(["c8"]),
  bun: Object.freeze(["bun-lcov"]),
  pytest: Object.freeze(["coverage.py"]),
});
const DIFF_COVERAGE_CANNOT_ATTEST_REASONS = [
  "coverage-provider-unavailable",
  "coverage-provider-version-mismatch",
  "coverage-run-failed",
  "coverage-report-missing",
  "coverage-report-invalid",
  "coverage-scope-invalid",
  "coverage-scope-incomplete",
  "coverage-py-unavailable",
  "coverage-acquisition-failed",
  "python-project-not-found",
  "pytest-unavailable",
  "python-target-unavailable",
];
const COUNT_KEYS = [
  "killed",
  "timeout",
  "survived",
  "no-coverage",
  "runtime-error",
  "build-error",
  "skipped-by-cap",
];
const CI_PROPERTY_OUTCOMES = [
  "pr-regression",
  "new-contract-counterexample",
  "source-grounded-test-gap",
  "pre-existing-counterexample",
  "possible-duplicate",
  "no-counterexample-found",
  "disagreement",
  "scenario-uncovered",
  "inconclusive",
  "not-applicable",
];

function fail(message) {
  throw new TypeError(`cannot prepare structural upload: ${message}`);
}

function object(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function requiredString(value, label, maximum = 1024) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    Buffer.byteLength(value, "utf8") > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail(`${label} must be a bounded printable string`);
  }
  return value;
}

function nullableString(value, label, maximum = 1024) {
  return value === null || value === undefined
    ? null
    : requiredString(value, label, maximum);
}

function repositoryPath(value, label) {
  const candidate = requiredString(value, label);
  if (
    candidate.startsWith("/") ||
    /^[A-Za-z]:/u.test(candidate) ||
    candidate.includes("\\") ||
    candidate.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${label} must be a canonical repository-relative POSIX path`);
  }
  return candidate;
}

function safeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function finiteOrNull(value, label) {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    fail(`${label} must be a finite number or null`);
  }
  return value;
}

function finite(value, label, minimum = Number.NEGATIVE_INFINITY, maximum = Number.POSITIVE_INFINITY) {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail(`${label} must be a finite number between ${minimum} and ${maximum}`);
  }
  return value;
}

function oneOf(value, permitted, label) {
  if (!permitted.includes(value)) fail(`${label} is invalid`);
  return value;
}

function structuralToken(value, label, maximum = 256) {
  const candidate = requiredString(value, label, maximum);
  if (!/^[A-Za-z0-9@][A-Za-z0-9._:/@+-]*$/u.test(candidate)) {
    fail(`${label} must be a structural token`);
  }
  return candidate;
}

function digestOrNull(value, label) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest or null`);
  }
  return value;
}

function ciPropertySearch(value) {
  if (value === null || value === undefined) return undefined;
  const input = object(value, "results.ciPropertySearch");
  const state = oneOf(
    input.state,
    ["completed", "partial", "unavailable", "disabled", "disabled-by-tier", "not-run"],
    "results.ciPropertySearch.state",
  );
  if (state !== "completed" && state !== "partial") {
    return {
      state,
      ...(input.reason === undefined
        ? {}
        : { reason: requiredString(input.reason, "results.ciPropertySearch.reason", 512) }),
    };
  }
  const counts = object(input.counts, "results.ciPropertySearch.counts");
  const byOutcome = object(counts.byOutcome, "results.ciPropertySearch.counts.byOutcome");
  const containerDigests = Array.isArray(input.containerDigests)
    ? input.containerDigests.map((digest, index) => {
        const checked = digestOrNull(
          digest,
          `results.ciPropertySearch.containerDigests[${index}]`,
        );
        if (checked === null) fail("results.ciPropertySearch.containerDigests cannot contain null");
        return checked;
      })
    : fail("results.ciPropertySearch.containerDigests must be an array");
  const models = Array.isArray(input.models)
    ? input.models.map((model, index) =>
        structuralToken(model, `results.ciPropertySearch.models[${index}]`, 256),
      )
    : fail("results.ciPropertySearch.models must be an array");
  if (containerDigests.length > 16 || models.length > 16) {
    fail("results.ciPropertySearch identity arrays exceed their 16-entry cap");
  }
  const requiredDigest = (value, label) => {
    const checked = digestOrNull(value, label);
    if (checked === null) fail(`${label} is required for a measured invariance run`);
    return checked;
  };
  const outcomeCounts = Object.fromEntries(
    CI_PROPERTY_OUTCOMES.map((outcome) => [
      outcome,
      safeInteger(byOutcome[outcome], `results.ciPropertySearch.counts.byOutcome.${outcome}`),
    ]),
  );
  const executedRules = safeInteger(
    counts.executedRules,
    "results.ciPropertySearch.counts.executedRules",
  );
  if (Object.values(outcomeCounts).reduce((sum, count) => sum + count, 0) !== executedRules) {
    fail("results.ciPropertySearch outcome counts must sum to executedRules");
  }
  const findings = safeInteger(counts.findings, "results.ciPropertySearch.counts.findings");
  if (
    outcomeCounts["pr-regression"] +
      outcomeCounts["new-contract-counterexample"] +
      outcomeCounts["source-grounded-test-gap"] !==
    findings
  ) {
    fail("results.ciPropertySearch finding outcomes must sum to findings");
  }
  const costUsd = finiteOrNull(input.costUsd, "results.ciPropertySearch.costUsd");
  if (costUsd !== null && costUsd < 0) {
    fail("results.ciPropertySearch.costUsd must be non-negative or null");
  }
  return {
    state,
    mode: oneOf(input.mode, ["shadow", "advisory"], "results.ciPropertySearch.mode"),
    candidateCap: oneOf(input.candidateCap, [1, 2, 4, 8], "results.ciPropertySearch.candidateCap"),
    counts: {
      selectedTargets: safeInteger(counts.selectedTargets, "results.ciPropertySearch.counts.selectedTargets"),
      validatedRules: safeInteger(counts.validatedRules, "results.ciPropertySearch.counts.validatedRules"),
      executedRules,
      findings,
      duplicatesSuppressed: safeInteger(counts.duplicatesSuppressed, "results.ciPropertySearch.counts.duplicatesSuppressed"),
      byOutcome: outcomeCounts,
    },
    ledgerDigest: requiredDigest(input.ledgerDigest, "results.ciPropertySearch.ledgerDigest"),
    evidencePackDigest: requiredDigest(input.evidencePackDigest, "results.ciPropertySearch.evidencePackDigest"),
    proofsDigest: requiredDigest(input.proofsDigest, "results.ciPropertySearch.proofsDigest"),
    containerDigests,
    models,
    llmCalls: safeInteger(input.llmCalls, "results.ciPropertySearch.llmCalls"),
    costUsd,
    wallMs: safeInteger(input.wallMs, "results.ciPropertySearch.wallMs"),
  };
}

function expectedRawCoverageFormat(provider) {
  if (provider === "v8" || provider === "babel" || provider === "c8") {
    return "istanbul-coverage-final-v1";
  }
  if (provider === "bun-lcov") return "lcov-v1";
  if (provider === "coverage.py") return "coverage-py-json-v1";
  return null;
}

function validateCoverageProviderForRunner(targetRunner, provider) {
  const normalizedTargetRunner = targetRunner.toLowerCase();
  const normalizedProviderRunner = provider.runner.toLowerCase();
  const normalizedProvider = provider.provider.toLowerCase();
  if (normalizedProviderRunner !== normalizedTargetRunner) {
    // Bounded npm-run-all aggregates measure Layer 0 through per-child NATIVE providers while
    // the baseline remains the wrapper command: target.runner is "command" and the provider
    // identity is "<child>-aggregate" (engine coverage.ts). Admit exactly that pairing — the
    // child runner must still carry an admissible provider — and hard-fail everything else.
    // Without this, every aggregate repo's completed Layer 0 was rejected at upload.
    const aggregate = /^([a-z-]+)-aggregate$/u.exec(normalizedProviderRunner);
    const childRunner = aggregate === null ? undefined : aggregate[1];
    if (
      normalizedTargetRunner === "command" &&
      childRunner !== undefined &&
      COVERAGE_PROVIDER_MATRIX[childRunner]?.includes(normalizedProvider)
    ) {
      return;
    }
    fail("results.diffCoverage.provider.runner must match results.target.runner");
  }
  if (!COVERAGE_PROVIDER_MATRIX[normalizedTargetRunner]?.includes(normalizedProvider)) {
    fail("results.diffCoverage.provider.provider is invalid for results.target.runner");
  }
}

/**
 * Translate legacy CLI v1 acquisition messages to the finite v2 wire vocabulary. The original
 * value is never copied into the upload, so provider diagnostics, parser excerpts, and paths stay
 * in the local CI artifact.
 */
function normalizeCannotAttestReason(value) {
  if (typeof value !== "string") return null;
  if (DIFF_COVERAGE_CANNOT_ATTEST_REASONS.includes(value)) return value;
  if (value === "coverage.py is not installed in the project's interpreter") {
    return "coverage-py-unavailable";
  }
  if (value === "coverage provider version mismatch") {
    return "coverage-provider-version-mismatch";
  }
  if (
    value === "coverage provider unavailable" ||
    value === "bundled coverage provider unavailable" ||
    value === "coverage unavailable" ||
    /^(?:jest|vitest|mocha|node-test|ava|tap|jasmine|bun|pytest) runner: no Layer 0 coverage provider$/u.test(
      value,
    )
  ) {
    return "coverage-provider-unavailable";
  }
  if (value === "coverage run exited nonzero (untrusted)") {
    return "coverage-run-failed";
  }
  if (
    value === "coverage report not produced" ||
    value === "coverage report was not produced"
  ) {
    return "coverage-report-missing";
  }
  if (
    value === "changed-file path cannot be represented by the coverage include filter" ||
    value === "empty scope"
  ) {
    return "coverage-scope-invalid";
  }
  if (
    value === "a requested changed file is missing from the coverage report" ||
    /^coverage report omits [1-9][0-9]* scoped file\(s\)$/u.test(value)
  ) {
    return "coverage-scope-incomplete";
  }
  if (
    value === "coverage json failed" ||
    value.startsWith("coverage report ") ||
    value.startsWith("lcov ")
  ) {
    return "coverage-report-invalid";
  }
  if (value === "coverage acquisition failed") {
    return "coverage-acquisition-failed";
  }
  return null;
}

function policyPattern(value, label) {
  const candidate = requiredString(value, label, 512);
  if (
    candidate.startsWith("/") ||
    /^[A-Za-z]:/u.test(candidate) ||
    candidate.includes("\\") ||
    candidate.includes("..")
  ) {
    fail(`${label} must be a repository-relative pattern`);
  }
  return candidate;
}

function boolean(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be boolean`);
  return value;
}

function optionalBoolean(value, label) {
  return value === undefined ? undefined : boolean(value, label);
}

function scope(raw, label) {
  if (!Array.isArray(raw)) fail(`${label} must be an array`);
  let expanded = 0;
  return raw.map((entry, index) => {
    const item = object(entry, `${label}[${index}]`);
    const file = repositoryPath(item.file, `${label}[${index}].file`);
    if (!Array.isArray(item.ranges) || item.ranges.length < 1) {
      fail(`${label}[${index}].ranges must be a non-empty array`);
    }
    let priorEnd = 0;
    const ranges = item.ranges.map((range, rangeIndex) => {
      if (
        !Array.isArray(range) ||
        range.length !== 2 ||
        !Number.isSafeInteger(range[0]) ||
        !Number.isSafeInteger(range[1]) ||
        range[0] < 1 ||
        range[1] < range[0] ||
        range[0] <= priorEnd
      ) {
        fail(`${label}[${index}].ranges[${rangeIndex}] is not canonical`);
      }
      priorEnd = range[1];
      expanded += range[1] - range[0] + 1;
      if (expanded > MAX_SCOPE_LINES) {
        fail(`${label} exceeds ${MAX_SCOPE_LINES} changed lines`);
      }
      return [range[0], range[1]];
    });
    return {
      file,
      ranges,
      lines: ranges.reduce((total, [start, end]) => total + end - start + 1, 0),
    };
  });
}

function coverageProvider(raw) {
  const provider = object(raw, "results.diffCoverage.provider");
  return {
    runner: structuralToken(provider.runner, "results.diffCoverage.provider.runner", 128),
    provider: structuralToken(provider.provider, "results.diffCoverage.provider.provider", 128),
    runnerVersion: nullableString(
      provider.runnerVersion,
      "results.diffCoverage.provider.runnerVersion",
      256,
    ),
    ...(provider.providerVersion !== undefined
      ? {
          providerVersion: nullableString(
            provider.providerVersion,
            "results.diffCoverage.provider.providerVersion",
            256,
          ),
        }
      : {}),
  };
}

function diffCoverage(raw) {
  if (raw === null || raw === undefined) return null;
  const input = object(raw, "results.diffCoverage");
  const state = oneOf(
    input.state,
    ["completed", "cannot-attest", "not-applicable", "not-run"],
    "results.diffCoverage.state",
  );
  const output = { state };
  if (input.wallMs !== undefined) {
    output.wallMs = finite(input.wallMs, "results.diffCoverage.wallMs", 0, 86_400_000);
  }
  if (input.acquisitionAttempts !== undefined) {
    // Retry-once disclosure: 2 means the first coverage run exited nonzero and was discarded
    // unread; the signed evidence derives from the green retry alone. Closed to {1,2}.
    output.acquisitionAttempts = oneOf(
      input.acquisitionAttempts,
      [1, 2],
      "results.diffCoverage.acquisitionAttempts",
    );
  }
  if (input.reason !== undefined && input.reason !== null) {
    const reason =
      state === "not-applicable"
        ? oneOf(
            input.reason,
            ["empty-scope", "no-executable-lines", "unsupported-runner"],
            "results.diffCoverage.reason",
          )
        : state === "not-run"
          ? oneOf(
              input.reason,
              ["baseline-abort", "pre-mutation-deadline"],
              "results.diffCoverage.reason",
            )
          : state === "cannot-attest"
            ? normalizeCannotAttestReason(input.reason)
            : requiredString(input.reason, "results.diffCoverage.reason", 160);
    if (state === "cannot-attest" && reason === null) {
      fail("results.diffCoverage.reason must be a recognized closed reason code");
    }
    output.reason = reason;
  } else if (state === "cannot-attest") {
    fail("results.diffCoverage.reason is required for cannot-attest");
  }
  if (input.provider !== undefined && input.provider !== null) {
    output.provider = coverageProvider(input.provider);
  }
  if (input.counts !== undefined) {
    const counts = object(input.counts, "results.diffCoverage.counts");
    output.counts = {
      changed: safeInteger(counts.changed, "results.diffCoverage.counts.changed"),
      covered: safeInteger(counts.covered, "results.diffCoverage.counts.covered"),
      uncovered: safeInteger(counts.uncovered, "results.diffCoverage.counts.uncovered"),
      notInstrumented: safeInteger(
        counts.notInstrumented,
        "results.diffCoverage.counts.notInstrumented",
      ),
      notExecutable: safeInteger(
        counts.notExecutable ?? 0,
        "results.diffCoverage.counts.notExecutable",
      ),
    };
  }
  if (input.lines !== undefined) {
    if (!Array.isArray(input.lines) || input.lines.length > MAX_SCOPE_LINES) {
      fail(`results.diffCoverage.lines must contain at most ${MAX_SCOPE_LINES} entries`);
    }
    output.lines = input.lines.map((entry, index) => {
      const line = object(entry, `results.diffCoverage.lines[${index}]`);
      return {
        file: repositoryPath(line.file, `results.diffCoverage.lines[${index}].file`),
        line: safeInteger(line.line, `results.diffCoverage.lines[${index}].line`, 1),
        state: oneOf(
          line.state,
          ["covered", "uncovered", "not-instrumented", "not-executable"],
          `results.diffCoverage.lines[${index}].state`,
        ),
      };
    });
  }
  return output;
}

/**
 * A model-written description, or null.
 *
 * Mirrors sanitizeFindingDescription in @abloh/core, which this file cannot import (it is a
 * standalone script the runner executes with no workspace resolution). Rejection is
 * all-or-nothing: a truncated leak is still a leak.
 */
function describableSentence(value, label) {
  if (typeof value !== "string") return null;
  /* Fold the punctuation a model actually writes into ASCII FIRST — em dashes, curly quotes
     and ellipses were each rejecting otherwise clean sentences. The ASCII rule that follows
     is not stylistic: it stops homoglyphs and direction overrides. */
  const text = value
    .trim()
    .replace(/\s+/gu, " ")
    .replace(/[\u2010-\u2015]/gu, "-")
    .replace(/[\u2018\u2019\u201A\u201B]/gu, "'")
    .replace(/[\u201C-\u201F]/gu, '"')
    .replace(/\u2026/gu, "...")
    .replace(/[\u00A0\u2007\u202F]/gu, " ");
  if (text.length === 0 || text.length > 200) return null;
  if (!/^[\x20-\x7E]*$/u.test(text)) return null;
  if (/[`{}]|=>|::/u.test(text)) return null;
  /* Possession is not quoting: elide the English apostrophes, refuse whatever quote is left. */
  if (/["']/u.test(text.replace(/(?<=[A-Za-z])'(?=[A-Za-z])|(?<=s)'(?![A-Za-z])/gu, ""))) return null;
  void label;
  return text;
}

function findings(raw) {
  if (!Array.isArray(raw)) return [];
  if (raw.length > MAX_FINDINGS) fail(`results.findings exceeds ${MAX_FINDINGS} entries`);
  return raw.map((entry, index) => {
    const finding = object(entry, `results.findings[${index}]`);
    const output = {
      mutantId: structuralToken(
        finding.mutantId,
        `results.findings[${index}].mutantId`,
        2048,
      ),
      file: repositoryPath(finding.file, `results.findings[${index}].file`),
      startLine: safeInteger(finding.startLine, `results.findings[${index}].startLine`, 1),
      endLine: safeInteger(finding.endLine, `results.findings[${index}].endLine`, 1),
      mutator: structuralToken(finding.mutator, `results.findings[${index}].mutator`, 128),
      status: oneOf(
        finding.status,
        ["survived", "no-coverage"],
        `results.findings[${index}].status`,
      ),
      coveredBy: safeInteger(finding.coveredBy ?? 0, `results.findings[${index}].coveredBy`),
    };
    if (finding.triage !== undefined && finding.triage !== null) {
      const triage = object(finding.triage, `results.findings[${index}].triage`);
      output.triage = {
        verdict: oneOf(
          triage.verdict,
          ["likely-equivalent", "real-gap", "unclear"],
          `results.findings[${index}].triage.verdict`,
        ),
        reasonCode: structuralToken(
          triage.reasonCode,
          `results.findings[${index}].triage.reasonCode`,
          128,
        ),
        confidence: finite(
          triage.confidence,
          `results.findings[${index}].triage.confidence`,
          0,
          1,
        ),
        overridden:
          triage.overridden === undefined
            ? null
            : boolean(triage.overridden, `results.findings[${index}].triage.overridden`),
        // Model prose, re-checked here rather than trusted from the artifact. Anything
        // that fails the check becomes null and the UI falls back to its template — a
        // rejected sentence must never be forwarded in a mangled form.
        description: describableSentence(
          triage.description,
          `results.findings[${index}].triage.description`,
        ),
        /*
         * The classifier identity. Safe to send because a project cannot choose it — a committed
         * policy file may not name a model, so these identify the service's own classifier and
         * never anything the customer wrote.
         *
         * Without them a run can never be marked triage-validated, which matches an exact
         * (model, prompt, effort) triple, and a human label on a verdict cannot be attributed to
         * what produced it.
         */
        modelId:
          triage.modelId === undefined || triage.modelId === null
            ? null
            : structuralToken(triage.modelId, `results.findings[${index}].triage.modelId`, 128),
        promptVersion:
          triage.promptVersion === undefined || triage.promptVersion === null
            ? null
            : structuralToken(
                triage.promptVersion,
                `results.findings[${index}].triage.promptVersion`,
                64,
              ),
        effort:
          triage.effort === undefined || triage.effort === null
            ? null
            : oneOf(
                triage.effort,
                ["low", "medium", "high", "xhigh"],
                `results.findings[${index}].triage.effort`,
              ),
      };
    }
    return output;
  });
}

function baseline(raw) {
  if (raw === null || raw === undefined) return null;
  const value = object(raw, "results.baseline");
  if (!Array.isArray(value.durationsMs) || value.durationsMs.length > 100) {
    fail("results.baseline.durationsMs must be a bounded array");
  }
  if (value.testCounts !== undefined && (!Array.isArray(value.testCounts) || value.testCounts.length > 100)) {
    fail("results.baseline.testCounts must be a bounded array");
  }
  return {
    runs: safeInteger(value.runs, "results.baseline.runs", 1),
    durationsMs: value.durationsMs.map((duration, index) =>
      finite(duration, `results.baseline.durationsMs[${index}]`, 0, 86_400_000),
    ),
    redBaseline: boolean(value.redBaseline, "results.baseline.redBaseline"),
    testCount:
      value.testCount === null || value.testCount === undefined
        ? null
        : safeInteger(value.testCount, "results.baseline.testCount"),
    testCounts:
      value.testCounts === undefined
        ? null
        : value.testCounts.map((count, index) =>
            safeInteger(count, `results.baseline.testCounts[${index}]`),
          ),
    testIdentityCount:
      value.testIdentityCount === null || value.testIdentityCount === undefined
        ? null
        : safeInteger(value.testIdentityCount, "results.baseline.testIdentityCount"),
    ambiguousIdentityCount:
      value.ambiguousIdentityCount === null || value.ambiguousIdentityCount === undefined
        ? null
        : safeInteger(value.ambiguousIdentityCount, "results.baseline.ambiguousIdentityCount"),
    flakyCount:
      value.flakyCount === null || value.flakyCount === undefined
        ? null
        : safeInteger(value.flakyCount, "results.baseline.flakyCount"),
    timingCv:
      value.timingCv === null || value.timingCv === undefined
        ? null
        : finite(value.timingCv, "results.baseline.timingCv", 0, 1000),
    timeoutFactor:
      value.timeoutFactor === null || value.timeoutFactor === undefined
        ? null
        : finite(value.timeoutFactor, "results.baseline.timeoutFactor", 0, 1000),
    quarantineDowngraded:
      value.quarantineDowngraded === null || value.quarantineDowngraded === undefined
        ? null
        : safeInteger(value.quarantineDowngraded, "results.baseline.quarantineDowngraded"),
  };
}

function structuralResults(raw) {
  const input = object(raw, "results");
  for (const retired of ["realisticMutants", "mutationSelection"]) {
    if (input[retired] !== undefined) {
      fail(`results.${retired} was retired before attest-results/v2`);
    }
  }
  const counts = object(input.counts, "results.counts");
  const scores = object(input.scores, "results.scores");
  const gate = object(input.gate, "results.gate");
  const target = object(input.target, "results.target");
  const engine = object(input.engine, "results.engine");
  const targetRunner = structuralToken(target.runner, "results.target.runner", 128);
  // Closed key set — pinned to TARGET_ARTIFACT_KEYS in @abloh/core capability-registry.ts by the
  // target-disclosure sync test. REJECT unknown keys instead of dropping them: a newer CLI running
  // against an older action must fail the upload loudly, never ship a silently stripped structural
  // copy under a digest that binds the richer raw artifact.
  const TARGET_ARTIFACT_KEYS = ["repo", "baseSha", "sha", "runner", "directory", "targetSelection"];
  for (const key of Object.keys(target)) {
    if (!TARGET_ARTIFACT_KEYS.includes(key)) fail(`results.target carries an unrecognized key: ${key}`);
  }
  // Optional on historical artifacts; validated whenever present.
  const targetDirectory = target.directory === undefined || target.directory === null
    ? target.directory
    : requiredString(target.directory, "results.target.directory", 512);
  if (typeof targetDirectory === "string" && (targetDirectory.startsWith("/") || targetDirectory.split("/").includes(".."))) {
    fail("results.target.directory must be a repository-relative path");
  }
  const targetSelection = target.targetSelection === undefined
    ? undefined
    : oneOf(
        target.targetSelection,
        ["declared-policy", "declared-cli", "auto-diff", "auto-diff-multi", "repository-root"],
        "results.target.targetSelection",
      );
  const floor =
    input.floor === null || input.floor === undefined
      ? null
      : (() => {
          const value = object(input.floor, "results.floor");
          return {
            passed: boolean(value.passed, "results.floor.passed"),
            ...(value.minMutantsExecuted !== undefined
              ? {
                  minMutantsExecuted: boolean(
                    value.minMutantsExecuted,
                    "results.floor.minMutantsExecuted",
                  ),
                }
              : {}),
            ...(value.maxErrorRate !== undefined
              ? { maxErrorRate: boolean(value.maxErrorRate, "results.floor.maxErrorRate") }
              : {}),
            ...(value.minSamplingFraction !== undefined
              ? {
                  minSamplingFraction: boolean(
                    value.minSamplingFraction,
                    "results.floor.minSamplingFraction",
                  ),
                }
              : {}),
          };
        })();
  const policy =
    input.policy === null || input.policy === undefined
      ? undefined
      : (() => {
          const value = object(input.policy, "results.policy");
          const output = {};
          if (value.threshold !== undefined) {
            output.threshold = finite(value.threshold, "results.policy.threshold", 0, 100);
          }
          if (value.tier !== undefined) {
            output.tier = oneOf(value.tier, [0, 1, 2], "results.policy.tier");
          }
          if (value.enforce !== undefined) {
            output.enforce = boolean(value.enforce, "results.policy.enforce");
          }
          if (value.floor !== undefined) {
            const policyFloor = object(value.floor, "results.policy.floor");
            output.floor = {
              minMutantsExecuted: safeInteger(
                policyFloor.minMutantsExecuted,
                "results.policy.floor.minMutantsExecuted",
              ),
              maxErrorRate: finite(
                policyFloor.maxErrorRate,
                "results.policy.floor.maxErrorRate",
                0,
                1,
              ),
              minSamplingFraction: finite(
                policyFloor.minSamplingFraction,
                "results.policy.floor.minSamplingFraction",
                0,
                1,
              ),
            };
          }
          if (Array.isArray(value.flaggedPaths)) {
            output.flaggedPaths = value.flaggedPaths.map((path, index) =>
              policyPattern(path, `results.policy.flaggedPaths[${index}]`),
            );
          }
          if (value.errorPaths !== undefined) {
            const errorPaths = object(value.errorPaths, "results.policy.errorPaths");
            output.errorPaths = {
              failOnUntested: optionalBoolean(
                errorPaths.failOnUntested,
                "results.policy.errorPaths.failOnUntested",
              ),
              failOnAntiPattern: optionalBoolean(
                errorPaths.failOnAntiPattern,
                "results.policy.errorPaths.failOnAntiPattern",
              ),
            };
          }
          return output;
        })();
  const sanitizedDiffCoverage =
    input.diffCoverage !== undefined ? diffCoverage(input.diffCoverage) : undefined;
  if (sanitizedDiffCoverage?.provider !== undefined) {
    validateCoverageProviderForRunner(targetRunner, sanitizedDiffCoverage.provider);
  }
  const rawCoverageDigest = digestOrNull(
    input.rawCoverageDigest,
    "results.rawCoverageDigest",
  );
  const rawCoverageFormat =
    input.rawCoverageFormat === null || input.rawCoverageFormat === undefined
      ? null
      : oneOf(
          input.rawCoverageFormat,
          RAW_COVERAGE_FORMATS,
          "results.rawCoverageFormat",
        );
  const measuredCoverage =
    sanitizedDiffCoverage?.state === "completed" ||
    (sanitizedDiffCoverage?.state === "not-applicable" &&
      sanitizedDiffCoverage.reason === "no-executable-lines");
  if ((rawCoverageDigest === null) !== (rawCoverageFormat === null)) {
    fail("results.rawCoverageDigest and results.rawCoverageFormat must appear together");
  }
  if (measuredCoverage) {
    if (rawCoverageDigest === null || rawCoverageFormat === null) {
      fail("measured diff coverage must carry a raw coverage digest and format");
    }
    const expectedFormat = expectedRawCoverageFormat(
      sanitizedDiffCoverage.provider?.provider,
    );
    if (expectedFormat === null || rawCoverageFormat !== expectedFormat) {
      fail("results.rawCoverageFormat does not match the measured coverage provider");
    }
  } else if (rawCoverageDigest !== null || rawCoverageFormat !== null) {
    fail("raw coverage evidence is invalid when diff coverage was not measured");
  }
  const sanitizedCiPropertySearch = ciPropertySearch(input.ciPropertySearch);

  return {
    schema: oneOf(input.schema, ["attest-results/v2"], "results.schema"),
    engine: {
      name: structuralToken(engine.name, "results.engine.name", 128),
      version: structuralToken(engine.version, "results.engine.version", 128),
    },
    target: {
      repo: requiredString(target.repo, "results.target.repo", 512),
      baseSha: structuralToken(target.baseSha, "results.target.baseSha", 128),
      sha: structuralToken(target.sha, "results.target.sha", 128),
      runner: targetRunner,
      ...(targetDirectory === undefined ? {} : { directory: targetDirectory }),
      ...(targetSelection === undefined ? {} : { targetSelection }),
    },
    tier: oneOf(input.tier, [0, 1, 2], "results.tier"),
    mutantsPlanned: safeInteger(input.mutantsPlanned, "results.mutantsPlanned"),
    mutantsRun: safeInteger(input.mutantsRun, "results.mutantsRun"),
    counts: Object.fromEntries(
      COUNT_KEYS.map((key) => [
        key,
        safeInteger(counts[key] ?? 0, `results.counts.${key}`),
      ]),
    ),
    scores: {
      rawScore:
        scores.rawScore === null
          ? null
          : finite(scores.rawScore, "results.scores.rawScore", 0, 100),
      triagedScore:
        scores.triagedScore === null
          ? null
          : finite(scores.triagedScore, "results.scores.triagedScore", 0, 100),
      denominator: safeInteger(scores.denominator, "results.scores.denominator"),
      confirmedEquivalent: safeInteger(
        scores.confirmedEquivalent,
        "results.scores.confirmedEquivalent",
      ),
      triageValidated: boolean(
        scores.triageValidated,
        "results.scores.triageValidated",
      ),
    },
    floor,
    gate: {
      status: oneOf(
        gate.status,
        ["pass", "fail", "cannot-attest"],
        "results.gate.status",
      ),
      score:
        gate.score === null ? null : finite(gate.score, "results.gate.score", 0, 100),
      threshold: finite(gate.threshold, "results.gate.threshold", 0, 100),
    },
    findings: findings(input.findings),
    baseline: baseline(input.baseline),
    skipBaseline: input.skipBaseline === true,
    /* WS3 widened keys — consistency with the live hosted producers (this file is not on the
       live workflow path; build-handoff.mjs + the template's embedded copy are). */
    ...(input.evidenceProfile === undefined || input.evidenceProfile === null ? {} : { evidenceProfile: input.evidenceProfile }),
    ...(Array.isArray(input.packages) ? { packages: input.packages.slice(0, 8) } : {}),
    ...(Array.isArray(input.mutantRoster) ? { mutantRoster: input.mutantRoster.slice(0, 20000) } : {}),
    uncommitted: input.uncommitted === true,
    ...(input.scope !== undefined ? { scope: scope(input.scope, "results.scope") } : {}),
    ...(sanitizedDiffCoverage !== undefined
      ? { diffCoverage: sanitizedDiffCoverage }
      : {}),
    ...(input.mutationExecution !== undefined
      ? (() => {
          const value = object(input.mutationExecution, "results.mutationExecution");
          const state = oneOf(
            value.state,
            ["completed", "skipped", "not-run"],
            "results.mutationExecution.state",
          );
          const execution = { state };
          if (state === "completed") {
            execution.scope = oneOf(
              value.scope,
              [
                "original",
                "covered-only",
                "covered-plus-error-handlers",
                "error-handlers-only",
              ],
              "results.mutationExecution.scope",
            );
            if (value.reason !== undefined && value.reason !== null) {
              fail("results.mutationExecution.reason is invalid when completed");
            }
          } else {
            if (value.scope !== undefined && value.scope !== null) {
              fail("results.mutationExecution.scope is invalid unless completed");
            }
            execution.reason = oneOf(
              value.reason,
              state === "skipped"
                ? ["layer-0-failed", "no-covered-changed-lines", "layer-0-unavailable"]
                : [
                    "empty-scope",
                    "baseline-abort",
                    "pre-mutation-deadline",
                    "no-runner",
                    "engine-error",
                  ],
              "results.mutationExecution.reason",
            );
          }
          return { mutationExecution: execution };
        })()
      : {}),
    ...(input.mutationScope !== undefined
      ? { mutationScope: scope(input.mutationScope, "results.mutationScope") }
      : {}),
    rawCoverageDigest,
    rawCoverageFormat,
    rawReportDigest: digestOrNull(input.rawReportDigest, "results.rawReportDigest"),
    rawCarrierDigest: digestOrNull(input.rawCarrierDigest, "results.rawCarrierDigest"),
    ...(policy !== undefined ? { policy } : {}),
    ...(sanitizedCiPropertySearch !== undefined
      ? { ciPropertySearch: sanitizedCiPropertySearch }
      : {}),
  };
}

export function buildStructuralUpload(rawResults, rawProvenance) {
  const provenance = object(rawProvenance, "provenance");
  const results = structuralResults(rawResults);
  const repository = requiredString(provenance.repository, "provenance.repository", 512);
  if (!/^[^/\s]+\/[^/\s]+$/u.test(repository)) {
    fail("provenance.repository must have owner/name form");
  }
  const headSha = requiredString(provenance.headSha, "provenance.headSha", 64);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(headSha)) {
    fail("provenance.headSha must be a full lowercase Git object id");
  }
  if (String(results.target.sha) !== headSha) {
    fail("results.target.sha must equal provenance.headSha");
  }
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(String(results.target.baseSha))) {
    fail("results.target.baseSha must be a full lowercase Git object id");
  }
  // The CLI target is intentionally a local filesystem path. It is useful inside CI but is
  // never valid control-plane data; bind the upload to GitHub's owner/repo identity instead.
  results.target.repo = repository;
  return {
    results,
    provenance: {
      repository,
      headSha,
      ...(provenance.pullRequest !== null && provenance.pullRequest !== undefined
        ? {
            pullRequest: safeInteger(
              Number(provenance.pullRequest),
              "provenance.pullRequest",
              1,
            ),
          }
        : {}),
      ...(provenance.ref !== null && provenance.ref !== undefined
        ? { ref: requiredString(provenance.ref, "provenance.ref", 512) }
        : {}),
      ...(provenance.ciRunId !== null && provenance.ciRunId !== undefined
        ? { ciRunId: requiredString(provenance.ciRunId, "provenance.ciRunId", 128) }
        : {}),
      ...(provenance.attempt !== null && provenance.attempt !== undefined
        ? { attempt: safeInteger(Number(provenance.attempt), "provenance.attempt", 1) }
        : {}),
      ...(provenance.prComment !== null && provenance.prComment !== undefined
        ? {
            prComment: oneOf(
              provenance.prComment,
              ["hosted", "cli", "off"],
              "provenance.prComment",
            ),
          }
        : {}),
    },
  };
}

function main() {
  const path = process.env.ABLOH_RESULTS_PATH;
  if (!path) fail("ABLOH_RESULTS_PATH is required");
  const size = statSync(path).size;
  if (size < 1 || size > MAX_INPUT_BYTES) {
    fail(`attest-results.json must be between 1 byte and ${MAX_INPUT_BYTES} bytes`);
  }
  const results = JSON.parse(readFileSync(path, "utf8"));
  const provenance = {
    repository: process.env.ABLOH_REPOSITORY,
    headSha: process.env.ABLOH_HEAD_SHA,
    pullRequest: process.env.ABLOH_PULL_REQUEST || null,
    ref: process.env.ABLOH_REF || null,
    ciRunId: process.env.ABLOH_CI_RUN_ID || null,
    attempt: process.env.ABLOH_CI_ATTEMPT || null,
    prComment: process.env.ABLOH_PR_COMMENT || "hosted",
  };
  process.stdout.write(`${JSON.stringify(buildStructuralUpload(results, provenance))}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
