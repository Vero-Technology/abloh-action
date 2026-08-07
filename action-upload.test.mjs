import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { uploadEvidence } from "./action-boundary.mjs";

/*
 * The composite Action's evidence upload.
 *
 * This is the step that makes a customer install work at all: the Action used to refuse to upload,
 * so a PR sat on "Waiting for CI evidence" forever. What makes it safe is that it holds no shared
 * secret — a GitHub OIDC identity is minted after measurement, used once, and passed to nothing.
 */

const SHA = "b".repeat(40);

function fixture(results) {
  const root = mkdtempSync(join(tmpdir(), "abloh-upload-"));
  const output = join(root, "out");
  mkdirSync(output);
  writeFileSync(join(output, "attest-results.json"), JSON.stringify(results));
  return { root, output };
}

const evidence = (tier = 1) => ({
  schema: "attest-results/v2",
  engine: { name: "stryker", version: "8.0.0" },
  target: { baseSha: "a".repeat(40), sha: SHA, runner: "vitest" },
  tier,
  mutantsPlanned: 0,
  mutantsRun: 0,
  findings: [],
});

function environmentFor(output) {
  return {
    ABLOH_OUTPUT_DIR: output,
    HANDOFF_URL: "https://api.abloh.example/api/v1/orgs/acme/runs",
    HANDOFF_AUDIENCE: "https://api.abloh.example/handoff",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.actions.githubusercontent.example/mint",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token",
    GITHUB_REPOSITORY: "acme/service",
    GITHUB_WORKFLOW_REF: "acme/service/.github/workflows/ci.yml@refs/heads/main",
    GITHUB_WORKFLOW_SHA: "c".repeat(40),
    GITHUB_RUN_ID: "777",
    GITHUB_RUN_ATTEMPT: "1",
    ABLOH_TRIGGER_SHA: "d".repeat(40),
    ABLOH_HEAD_SHA: SHA,
    ABLOH_PULL_REQUEST: "42",
  };
}

/** A fetch double: first call mints the identity, second is the upload. */
function fetchDouble({ mintOk = true, uploadStatus = 201 } = {}) {
  const calls = [];
  const impl = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (calls.length === 1) {
      return mintOk
        ? { ok: true, json: async () => ({ value: "header.payload.signature" }) }
        : { ok: false, json: async () => ({}) };
    }
    return { ok: uploadStatus < 400, status: uploadStatus, json: async () => ({}) };
  };
  return { impl, calls };
}

test("the upload mints an identity, then posts the envelope with it", async () => {
  const { output } = fixture(evidence());
  const { impl, calls } = fetchDouble();
  assert.equal(await uploadEvidence(environmentFor(output), impl), 0);
  assert.equal(calls.length, 2, "one mint, one post");

  /* The mint asks GitHub for the configured audience — nothing else is sent. */
  assert.match(calls[0].url, /audience=https%3A%2F%2Fapi\.abloh\.example%2Fhandoff/u);
  assert.equal(calls[0].init.headers.authorization, "Bearer request-token");

  /* The upload carries the minted identity, not any shared secret. */
  const post = calls[1];
  assert.equal(post.url, "https://api.abloh.example/api/v1/orgs/acme/runs");
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.headers.authorization, "Bearer header.payload.signature");

  const envelope = JSON.parse(post.init.body);
  assert.equal(envelope.schema, "abloh-ci-handoff/v2");
  assert.equal(envelope.provenance.headSha, SHA);
  assert.equal(envelope.provenance.repository, "acme/service");
});

test("the artifact digest is computed from the bytes actually sent", async () => {
  /*
   * contextFromEnvironment reads the digest from ABLOH_LOCAL_ARTIFACT_DIGEST, which the reusable
   * workflow sets from a shell sha256sum. This step has no such shell local, and an absent value
   * becomes "" — which the control plane refuses. So it is computed here, and this asserts it matches
   * the file rather than being some other run's digest.
   */
  const results = evidence();
  const { output } = fixture(results);
  const { impl, calls } = fetchDouble();
  await uploadEvidence(environmentFor(output), impl);
  const envelope = JSON.parse(calls[1].init.body);
  const expected = createHash("sha256").update(JSON.stringify(results)).digest("hex");
  assert.equal(envelope.artifactDigest, `sha256:${expected}`);
});

test("tier-2 sidecars are picked up beside the artifact; tier 1 sends none", async () => {
  const rationales = JSON.stringify({ schema: "attest-rationales/v1", rationales: { m: "why" } });

  const two = fixture(evidence(2));
  writeFileSync(join(two.output, "attest-rationales.json"), rationales);
  const first = fetchDouble();
  await uploadEvidence(environmentFor(two.output), first.impl);
  const withSidecars = JSON.parse(first.calls[1].init.body);
  assert.equal(withSidecars.sidecars.rationales, rationales, "bytes forwarded verbatim");

  const one = fixture(evidence(1));
  writeFileSync(join(one.output, "attest-rationales.json"), rationales);
  const second = fetchDouble();
  await uploadEvidence(environmentFor(one.output), second.impl);
  const below = JSON.parse(second.calls[1].init.body);
  assert.ok(!Object.hasOwn(below, "sidecars"), "tier 1 must not send them even when present on disk");
});

test("a refused upload fails the step and does not echo the remote body", async () => {
  /* The status is disclosed; the body is not. A remote string in a public build log is how a
     service's internals end up somewhere the customer can read them. */
  const { output } = fixture(evidence());
  const { impl } = fetchDouble({ uploadStatus: 403 });
  await assert.rejects(() => uploadEvidence(environmentFor(output), impl), /HTTP 403/u);
});

test("a failed mint fails the step before anything is posted", async () => {
  const { output } = fixture(evidence());
  const { impl, calls } = fetchDouble({ mintOk: false });
  await assert.rejects(() => uploadEvidence(environmentFor(output), impl), /could not mint/u);
  assert.equal(calls.length, 1, "nothing is posted without an identity");
});

test("a missing handoff URL or audience is refused, not silently skipped", async () => {
  const { output } = fixture(evidence());
  const { impl } = fetchDouble();
  const base = environmentFor(output);
  await assert.rejects(() => uploadEvidence({ ...base, HANDOFF_URL: "" }, impl), /handoff-url/u);
  await assert.rejects(() => uploadEvidence({ ...base, HANDOFF_AUDIENCE: "" }, impl), /handoff-audience/u);
  /* And a non-HTTPS or credential-bearing URL never gets a token minted for it. */
  await assert.rejects(
    () => uploadEvidence({ ...base, HANDOFF_URL: "http://api.abloh.example/x" }, impl),
    /handoff-url/u,
  );
});
