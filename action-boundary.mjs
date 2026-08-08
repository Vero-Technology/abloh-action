#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  closeSync,
  readFileSync,
  realpathSync,
  statSync,
  writeSync,
} from "node:fs";
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const SHA = /^[0-9a-f]{40}$/u;
const RUN_NUMBER = /^[1-9][0-9]*$/u;
const IMAGE = /^[A-Za-z0-9][^@\s]*@sha256:[0-9a-f]{64}$/u;
const SEED = /^[0-9a-fA-F]{1,64}$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const PULL_REQUEST_OVERRIDE_INPUTS = [
  ["TIER", "tier"],
  ["SUBDIR", "subdir"],
  ["POLICY", "policy"],
  ["ENVIRONMENT_IMAGE", "environment-image"],
  ["TEST_COMMAND", "test-command"],
  ["SEED", "seed"],
];
const CONTROL_PLANE_SECRETS = [
  "ABLOH_API_TOKEN",
  "API_TOKEN",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "ACTIONS_RUNTIME_TOKEN",
  "ACTIONS_CACHE_SERVICE_V2",
  "ACTIONS_RESULTS_URL",
];
const INSTALL_SECRETS = [
  ...CONTROL_PLANE_SECRETS,
  "ANTHROPIC_API_KEY",
  "ATTEST_MODEL_API_KEY",
  "ATTEST_MODEL_API_KEY_ALT",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "OPENAI_API_KEY",
];
const DIRECT_MODEL_SECRETS = [
  "ANTHROPIC_API_KEY",
  "ATTEST_MODEL_API_KEY",
  "ATTEST_MODEL_API_KEY_ALT",
  "OPENAI_API_KEY",
];

function fail(message) {
  throw new Error(`Abloh Action boundary: ${message}`);
}

function required(value, label) {
  if (typeof value !== "string" || value.length === 0 || CONTROL.test(value)) {
    fail(`${label} must be a non-empty control-free string`);
  }
  return value;
}

function optional(value, label) {
  if (value === undefined || value === "") return "";
  if (CONTROL.test(value)) fail(`${label} must not contain control characters`);
  return value;
}

function credentialFreeHttps(value, label) {
  const candidate = required(value, label);
  let url;
  try {
    url = new URL(candidate);
  } catch {
    fail(`${label} must be an HTTPS URL`);
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    fail(`${label} must be credential-free HTTPS without query or fragment`);
  }
  return url.toString();
}

function sha(value, label) {
  const candidate = required(value, label);
  if (!SHA.test(candidate)) fail(`${label} must be a lowercase 40-character commit SHA`);
  return candidate;
}

function canonicalRelative(value, label, allowDot = false) {
  const candidate = required(value, label);
  if (allowDot && candidate === ".") return candidate;
  if (
    isAbsolute(candidate) ||
    candidate.startsWith("-") ||
    /^[A-Za-z]:/u.test(candidate) ||
    candidate.includes("\\") ||
    candidate.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${label} must be a canonical relative POSIX path`);
  }
  return candidate;
}

function assertTrustedPullRequestInputs(environment) {
  if (environment.GITHUB_EVENT_NAME !== "pull_request") return;
  const supplied = PULL_REQUEST_OVERRIDE_INPUTS
    .filter(([name]) => optional(environment[name], name) !== "")
    .map(([, label]) => label);
  if (supplied.length > 0) {
    fail(
      `pull_request runs must derive measurement settings from the trusted merge-base abloh.yml; ` +
      `remove Action override input${supplied.length === 1 ? "" : "s"}: ${supplied.join(", ")}`,
    );
  }
}

export function validateActionInputs(environment = process.env) {
  assertTrustedPullRequestInputs(environment);
  const tier = optional(environment.TIER, "tier");
  if (tier !== "" && !/^[012]$/u.test(tier)) fail("tier must be 0, 1, or 2");
  const upload = required(environment.UPLOAD ?? "false", "upload");
  if (upload !== "true" && upload !== "false") fail("upload must be true or false");
  /*
   * UPLOAD IS ALLOWED, AND CARRIES NO LONG-LIVED CREDENTIAL.
   *
   * This used to refuse outright, on the grounds that uploading needs a token and a job running
   * customer code cannot hold one. That premise was about SHARED SECRETS. The upload below uses a
   * GitHub OIDC identity instead: minted here, scoped to one audience, valid for minutes, and
   * authorizing exactly one thing — posting evidence about this repository at this commit, which is
   * something a job that already runs the customer's tests can do regardless.
   *
   * What it still cannot do is prove ABLOH'S code did the measuring: a composite action is inlined
   * into the caller's job, so GitHub attests the repository, not the producer. The control plane
   * records no artifact digest for this path, so a certificate from it reads `standard` rather than
   * `service-verified`. The limit is stated in the grade instead of by refusing to upload at all.
   */
  if (optional(environment.PR_COMMENT, "pr-comment") !== "") {
    fail(
      "PR reporting is unavailable in the composite Action; use a separate " +
      "no-checkout privileged job or the Abloh GitHub App",
    );
  }
  const subdir = optional(environment.SUBDIR, "subdir");
  const policy = optional(environment.POLICY, "policy");
  const image = optional(environment.ENVIRONMENT_IMAGE, "environment-image");
  const testCommand = optional(environment.TEST_COMMAND, "test-command");
  const seedValue = optional(environment.SEED, "seed");
  if (subdir !== "") canonicalRelative(subdir, "subdir");
  if (policy !== "") canonicalRelative(policy, "policy");
  if (image !== "" && !IMAGE.test(image)) {
    fail("environment-image must be an immutable name@sha256:digest reference");
  }
  if (testCommand.startsWith("--")) fail("test-command must begin with an executable, not an option");
  if (seedValue !== "" && !SEED.test(seedValue)) fail("seed must be 1 to 64 hexadecimal characters");
  /*
   * The model gateway is OPTIONAL, and cannot be anything else here.
   *
   * Requiring it refused runs that would never have called a model: Layer 0, mutation and
   * reverse-patch are entirely mechanical, so a tier-0 repository was stopped before its first
   * step with "model-gateway-url must be a non-empty control-free string" and could not use the
   * Action at all. Nor can this boundary decide the question by reading the tier — on a
   * pull_request event `assertTrustedPullRequestInputs` refuses a `tier` input outright, because
   * measurement settings must come from the trusted merge-base abloh.yml, which is not parsed
   * here. So the tier is unknown at exactly the moment the requirement would have to be judged.
   *
   * Absence is therefore carried through: `runAbloh` mints no identity and injects no model
   * environment. Nothing degrades silently as a result — a policy that names a hosted provider
   * fails in `resolveProvider` with "ATTEST_MODEL_ENDPOINT is not set", which names the missing
   * thing at the moment it is actually needed. That is a better error than this one, and it is
   * the only place with enough information to raise it.
   *
   * A gateway that IS supplied is still validated here rather than ignored: a malformed value a
   * reader believes is in force must be refused where it is written.
   */
  if (optional(environment.MODEL_GATEWAY_URL, "model-gateway-url") !== "") {
    credentialFreeHttps(environment.MODEL_GATEWAY_URL, "model-gateway-url");
    const audience = required(environment.MODEL_GATEWAY_AUDIENCE, "model-gateway-audience");
    if (audience.length > 512) fail("model-gateway-audience is too long");
  }
  /*
   * The handoff pair is checked HERE, not only in uploadEvidence.
   *
   * It used to be validated for the first time in the upload step — the last thing the Action does.
   * A half-configured handoff therefore ran the whole measurement first: baseline, coverage,
   * mutation, and a reverse-patch lane costing about twice the customer's suite, all of it
   * published to a staging directory and then thrown away on "handoff-audience must be a non-empty
   * control-free string". Minutes of a customer's CI spent to report a missing input that was
   * knowable before the first test ran.
   *
   * Same shape as the gateway above: no handoff configured is fine and means no upload; a URL
   * without its audience is half-configured and refused up front. uploadEvidence still validates
   * both at the point of use, because that is the boundary that must not be bypassed.
   */
  if (optional(environment.HANDOFF_URL, "handoff-url") !== "") {
    credentialFreeHttps(environment.HANDOFF_URL, "handoff-url");
    const handoffAudience = required(environment.HANDOFF_AUDIENCE, "handoff-audience");
    if (handoffAudience.length > 512) fail("handoff-audience is too long");
  }
}

function inside(root, candidate, allowRoot = true) {
  const rel = relative(root, candidate);
  if (rel === "") return allowRoot;
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

function executableOnPath(name, environment) {
  for (const entry of (environment.PATH ?? "").split(delimiter)) {
    if (entry === "") continue;
    const candidate = join(entry, name);
    try {
      accessSync(candidate, constants.X_OK);
      if (lstatSync(candidate).isFile() || lstatSync(candidate).isSymbolicLink()) return true;
    } catch {
      // Keep looking. PATH entries are allowed to be absent.
    }
  }
  return false;
}

function git(repositoryRoot, args, environment) {
  const result = spawnSync("git", ["-C", repositoryRoot, ...args], {
    encoding: "utf8",
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) {
    const detail = String(result.stderr ?? "").trim();
    fail(`git ${args[0] ?? "command"} failed${detail === "" ? "" : `: ${detail}`}`);
  }
  return String(result.stdout).trim();
}

function appendOutput(path, fields) {
  const output = required(path, "GITHUB_OUTPUT");
  const info = lstatSync(output);
  if (info.isSymbolicLink() || !info.isFile()) fail("GITHUB_OUTPUT must be a regular non-symlink file");
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = openSync(output, constants.O_WRONLY | constants.O_APPEND | noFollow, 0o600);
  try {
    for (const [name, value] of Object.entries(fields)) {
      if (!/^[a-z][a-z0-9-]*$/u.test(name) || CONTROL.test(value)) {
        fail("refusing an unsafe GitHub output field");
      }
      // Values produced here are canonical paths, booleans, or commit SHAs. All are one line.
      writeAll(handle, `${name}=${value}\n`);
    }
  } finally {
    closeSync(handle);
  }
}

// Isolated to make it impossible to accidentally use a shell redirection for GITHUB_OUTPUT.
function writeAll(handle, value) {
  const bytes = Buffer.from(value, "utf8");
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(
      handle,
      bytes,
      offset,
      bytes.length - offset,
    );
    offset += written;
  }
}

function privateDirectory(parent, parts, leafMustBeNew = false) {
  const canonicalParent = realpathSync(required(parent, "RUNNER_TEMP"));
  if (!lstatSync(canonicalParent).isDirectory()) fail("RUNNER_TEMP must be a directory");
  let current = canonicalParent;
  for (const [index, part] of parts.entries()) {
    if (!/^[A-Za-z0-9._-]+$/u.test(part) || part === "." || part === "..") {
      fail("private staging path contains an unsafe segment");
    }
    const next = join(current, part);
    const existed = existsSync(next);
    if (leafMustBeNew && index === parts.length - 1 && existed) {
      fail(`private staging leaf already exists: ${next}`);
    }
    if (!existed) mkdirSync(next, { mode: 0o700 });
    const info = lstatSync(next);
    if (info.isSymbolicLink() || !info.isDirectory()) {
      fail(`private staging path is not a real directory: ${next}`);
    }
    const canonical = realpathSync(next);
    if (!inside(canonicalParent, canonical, false)) fail("private staging path escaped RUNNER_TEMP");
    chmodSync(canonical, 0o700);
    current = canonical;
  }
  return current;
}

function requireWorkingCommand(command, args, environment, message) {
  const result = spawnSync(command, args, {
    env: environment,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) fail(message);
}

export function assertSupportedNodeVersion(version = process.versions.node) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/u.exec(version);
  if (match === null) fail("cannot determine the prepared Node runtime version");
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (major < 20 || (major === 20 && minor < 6)) {
    fail(`Node ${version} is unsupported; set up the repository's Node >=20.6 runtime before Abloh`);
  }
}

export function preflight(environment = process.env) {
  if (environment.GITHUB_EVENT_NAME === "pull_request_target") {
    fail("pull_request_target is unsafe because untrusted pull-request code can receive base-repository secrets; use pull_request");
  }
  for (const tool of ["git", "node", "npm", "docker"]) {
    if (!executableOnPath(tool, environment)) fail(`${tool} must be installed before Abloh`);
  }
  assertSupportedNodeVersion();
  requireWorkingCommand("npm", ["--version"], environment, "npm must work before Abloh");
  requireWorkingCommand(
    "docker",
    ["info", "--format", "{{.ServerVersion}}"],
    environment,
    "Docker must have a reachable daemon before isolated HEAD/fault proofs",
  );
  validateActionInputs(environment);
  const workspace = realpathSync(required(environment.GITHUB_WORKSPACE, "GITHUB_WORKSPACE"));
  const repoPath = canonicalRelative(environment.REPO_PATH ?? ".", "repo-path", true);
  const lexicalRepository = resolve(workspace, repoPath);
  if (!inside(workspace, lexicalRepository)) fail("repo-path must stay inside GITHUB_WORKSPACE");
  if (!existsSync(lexicalRepository)) fail("repo-path does not exist");
  const requestedDirectory = realpathSync(lexicalRepository);
  if (!inside(workspace, requestedDirectory)) fail("repo-path resolves outside GITHUB_WORKSPACE");
  if (!lstatSync(requestedDirectory).isDirectory()) fail("repo-path must name a directory");
  const repositoryRoot = realpathSync(
    git(requestedDirectory, ["rev-parse", "--show-toplevel"], environment),
  );
  if (!inside(workspace, repositoryRoot) || !inside(repositoryRoot, requestedDirectory)) {
    fail("discovered Git repository must stay inside GITHUB_WORKSPACE and contain repo-path");
  }

  const eventName = required(environment.GITHUB_EVENT_NAME, "GITHUB_EVENT_NAME");
  const declaredBase = optional(environment.DECLARED_BASE, "base");
  let expectedHead;
  let effectiveBase;
  if (eventName === "pull_request") {
    expectedHead = sha(environment.PR_HEAD_SHA, "pull-request head");
    effectiveBase = sha(environment.PR_BASE_SHA, "pull-request base");
  } else {
    expectedHead = sha(environment.GITHUB_SHA_VALUE, "github.sha");
    if (declaredBase === "") fail("base is required outside a pull_request event");
    if (declaredBase.startsWith("-")) fail("base must not begin with '-'");
    effectiveBase = git(repositoryRoot, ["rev-parse", "--verify", `${declaredBase}^{commit}`], environment);
    sha(effectiveBase, "resolved base");
  }

  const actualHead = git(repositoryRoot, ["rev-parse", "--verify", "HEAD^{commit}"], environment);
  if (actualHead !== expectedHead) {
    fail(`exact pull-request head required; expected ${expectedHead}, found ${actualHead}`);
  }
  git(repositoryRoot, ["cat-file", "-e", `${effectiveBase}^{commit}`], environment);
  if (eventName === "pull_request" && declaredBase !== "") {
    if (declaredBase.startsWith("-")) fail("base must not begin with '-'");
    const declaredSha = git(
      repositoryRoot,
      ["rev-parse", "--verify", `${declaredBase}^{commit}`],
      environment,
    );
    if (declaredSha !== effectiveBase) {
      fail(`declared base resolves to ${declaredSha}, but the pull-request base is ${effectiveBase}`);
    }
  }

  const runId = required(environment.GITHUB_RUN_ID, "GITHUB_RUN_ID");
  const runAttempt = required(environment.GITHUB_RUN_ATTEMPT, "GITHUB_RUN_ATTEMPT");
  if (!RUN_NUMBER.test(runId) || !RUN_NUMBER.test(runAttempt)) fail("run id and attempt must be positive integers");
  const runnerTemp = realpathSync(required(environment.RUNNER_TEMP, "RUNNER_TEMP"));
  for (const candidate of [
    join(runnerTemp, "abloh", `${runId}-${runAttempt}`),
    join(runnerTemp, "abloh-state", `${runId}-${runAttempt}`),
    join(runnerTemp, "abloh-cli", `${runId}-${runAttempt}`),
  ]) {
    if (inside(repositoryRoot, candidate) || inside(candidate, repositoryRoot)) {
      fail("Action-owned output, state, and CLI paths must not overlap the measured repository");
    }
  }
  const outputDirectory = privateDirectory(environment.RUNNER_TEMP, [
    "abloh",
    `${runId}-${runAttempt}`,
  ], true);

  const stateDirectory = privateDirectory(environment.RUNNER_TEMP, [
    "abloh-state",
    `${runId}-${runAttempt}`,
  ], true);
  const baselineDirectory = join(stateDirectory, "baseline-history");
  // Deliberately fresh on every run, never restored from GitHub cache: cache contents are
  // repository-controlled and a self-authored receipt cannot make restored executable code
  // trusted. The "Prepare coverage provider cache" step populates it within THIS run via
  // `abloh prepare` (npm install with scripts disabled, receipt-validated by the CLI before
  // use); it also stops the CLI consulting a user-level cache outside the Action boundary.
  const coverageCacheDirectory = join(stateDirectory, "coverage-providers-fresh");
  mkdirSync(baselineDirectory, { mode: 0o700 });
  mkdirSync(coverageCacheDirectory, { mode: 0o700 });

  return {
    repositoryRoot,
    expectedHead,
    effectiveBase,
    outputDirectory,
    baselineDirectory,
    coverageCacheDirectory,
  };
}

/**
 * The published CLI this action installs when the caller names nothing.
 *
 * PINNED, not `latest`. This action is itself referenced by a 40-character commit SHA, so a caller
 * who pinned it has already decided which Abloh they are running; resolving `latest` at run time
 * would quietly change that for them. The version moves when a release moves it.
 */
export const DEFAULT_CLI_SPEC = "@abloh/cli@0.1.3";

export function parsePackageSpecs(value) {
  /*
   * `cli-tarball` was REQUIRED, because nothing was on npm: every caller had to pack the CLI and
   * its six workspace dependencies and pass all seven paths. That is why the only repository that
   * could run this action was ours. With @abloh/cli published, absent means "install the release".
   */
  const input = typeof value === "string" ? value.trim() : "";
  if (input === "") return [DEFAULT_CLI_SPEC];
  const specs = input.split(/\s+/u);
  if (specs.length === 0 || specs.length > 20) fail("cli-tarball must contain 1 to 20 package specs");
  for (const spec of specs) {
    if (spec.startsWith("-") || CONTROL.test(spec)) fail("cli-tarball contains an unsafe package spec");
  }
  return specs;
}

export function installCli(environment = process.env) {
  const runId = required(environment.GITHUB_RUN_ID, "GITHUB_RUN_ID");
  const runAttempt = required(environment.GITHUB_RUN_ATTEMPT, "GITHUB_RUN_ATTEMPT");
  if (!RUN_NUMBER.test(runId) || !RUN_NUMBER.test(runAttempt)) fail("run id and attempt must be positive integers");
  const prefix = privateDirectory(environment.RUNNER_TEMP, [
    "abloh-cli",
    `${runId}-${runAttempt}`,
  ], true);
  const installEnvironment = { ...environment, npm_config_ignore_scripts: "true" };
  for (const key of INSTALL_SECRETS) delete installEnvironment[key];
  const result = spawnSync(
    "npm",
    [
      "install",
      "-g",
      "--prefix",
      prefix,
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--",
      ...parsePackageSpecs(environment.CLI_TARBALL),
    ],
    { env: installEnvironment, stdio: "inherit" },
  );
  if (result.error || result.status !== 0) fail(`npm could not install the Abloh CLI (exit ${result.status ?? "unknown"})`);
  const cli = join(prefix, "bin", "abloh");
  if (!existsSync(cli)) fail("installed package did not provide the abloh executable");
  accessSync(cli, constants.X_OK);
  const target = realpathSync(cli);
  if (!inside(prefix, target, false) || !lstatSync(target).isFile()) {
    fail("installed abloh executable resolves outside its private package prefix");
  }
  return { cli, prefix };
}

export function buildRunArguments(environment = process.env) {
  assertTrustedPullRequestInputs(environment);
  const repositoryRoot = realpathSync(required(environment.REPOSITORY_ROOT, "repository root"));
  const base = sha(environment.BASE, "base");
  const head = sha(environment.HEAD_SHA, "head");
  const tier = optional(environment.TIER, "tier");
  if (tier !== "" && !/^[012]$/u.test(tier)) fail("tier must be 0, 1, or 2");
  const outputDirectory = realpathSync(required(environment.ABLOH_OUTPUT_DIR, "output directory"));
  const runnerTemp = realpathSync(required(environment.RUNNER_TEMP, "RUNNER_TEMP"));
  if (!inside(runnerTemp, outputDirectory, false)) fail("output directory must stay inside RUNNER_TEMP");
  if (inside(repositoryRoot, outputDirectory) || inside(outputDirectory, repositoryRoot)) {
    fail("output directory and measured repository must not overlap");
  }

  const args = ["run", "--repo", repositoryRoot, "--base", base, "--head", head];
  const subdir = optional(environment.SUBDIR, "subdir");
  const policy = optional(environment.POLICY, "policy");
  const image = optional(environment.ENVIRONMENT_IMAGE, "environment-image");
  const testCommand = optional(environment.TEST_COMMAND, "test-command");
  const seed = optional(environment.SEED, "seed");
  if (tier !== "") args.push("--tier", tier);
  if (subdir !== "") args.push("--subdir", canonicalRelative(subdir, "subdir"));
  if (policy !== "") args.push("--policy", canonicalRelative(policy, "policy"));
  if (image !== "") {
    if (!IMAGE.test(image)) fail("environment-image must be an immutable name@sha256:digest reference");
    args.push("--environment-image", image);
  }
  if (testCommand !== "") args.push("--test-command", testCommand);
  if (seed !== "") {
    if (!SEED.test(seed)) fail("seed must be 1 to 64 hexadecimal characters");
    args.push("--seed", seed);
  }
  args.push(
    "--json", join(outputDirectory, "attest-results.json"),
    "--md", join(outputDirectory, "attest-summary.md"),
    "--rationales", join(outputDirectory, "attest-rationales.json"),
  );
  return args;
}

/** Validate the gateway target without minting — the credential is obtained at the point of use. */
export function validatedModelGatewayTarget(environment = process.env) {
  for (const name of DIRECT_MODEL_SECRETS) {
    if (optional(environment[name], name) !== "") {
      fail(
        `${name} must not be supplied to the customer Action; configure the provider ` +
        `credential only on the Abloh model gateway`,
      );
    }
  }
  const gatewayUrl = credentialFreeHttps(environment.MODEL_GATEWAY_URL, "model-gateway-url");
  const audience = required(environment.MODEL_GATEWAY_AUDIENCE, "model-gateway-audience");
  if (audience.length > 512) fail("model-gateway-audience is too long");
  return { gatewayUrl, audience };
}

export async function requestModelGatewayIdentity(environment = process.env, fetchImpl = fetch) {
  for (const name of DIRECT_MODEL_SECRETS) {
    if (optional(environment[name], name) !== "") {
      fail(
        `${name} must not be supplied to the customer Action; configure the provider ` +
        `credential only on the Abloh model gateway`,
      );
    }
  }
  const gatewayUrl = credentialFreeHttps(
    environment.MODEL_GATEWAY_URL,
    "model-gateway-url",
  );
  const audience = required(environment.MODEL_GATEWAY_AUDIENCE, "model-gateway-audience");
  if (audience.length > 512) fail("model-gateway-audience is too long");
  return { gatewayUrl, token: await mintGitHubIdentity(environment, audience, "model-gateway", fetchImpl) };
}

/**
 * A short-lived GitHub OIDC identity for one audience.
 *
 * THIS IS WHY THE ACTION NEEDS NO API KEY. GitHub mints a JWT scoped to one audience, valid for
 * minutes, signed by GitHub, and carrying the repository and commit as claims the runner cannot
 * forge. It authorizes exactly one thing — talking to the service that audience names — so leaking it
 * grants nothing a job that already runs the customer's tests did not have.
 *
 * `ACTIONS_ID_TOKEN_REQUEST_TOKEN` is in CONTROL_PLANE_SECRETS, so it is stripped from every child
 * process this action spawns: the measured test suite and its dependencies cannot mint identities of
 * their own through us.
 */
export async function mintGitHubIdentity(
  environment,
  audience,
  label,
  fetchImpl = fetch,
) {
  const requestUrl = new URL(required(
    environment.ACTIONS_ID_TOKEN_REQUEST_URL,
    "GitHub OIDC request URL",
  ));
  if (requestUrl.protocol !== "https:" || requestUrl.username || requestUrl.password || requestUrl.hash) {
    fail("GitHub OIDC request URL is invalid");
  }
  requestUrl.searchParams.set("audience", audience);
  const requestToken = required(
    environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    "GitHub OIDC request token",
  );
  let response;
  try {
    response = await fetchImpl(requestUrl, {
      headers: { authorization: `Bearer ${requestToken}`, accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    fail(`GitHub could not mint the ${label} identity`);
  }
  if (!response.ok) fail(`GitHub could not mint the ${label} identity`);
  let body;
  try {
    body = await response.json();
  } catch {
    fail(`GitHub returned an invalid ${label} identity`);
  }
  const token = required(body?.value, `GitHub ${label} identity`);
  if (token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token)) {
    fail(`GitHub returned an invalid ${label} identity`);
  }
  return token;
}

export function buildPrepareArguments(environment = process.env) {
  assertTrustedPullRequestInputs(environment);
  const repositoryRoot = realpathSync(required(environment.REPOSITORY_ROOT, "repository root"));
  const runnerTemp = realpathSync(required(environment.RUNNER_TEMP, "RUNNER_TEMP"));
  const cacheDirectory = realpathSync(
    required(environment.ABLOH_COVERAGE_PROVIDER_CACHE_DIR, "coverage cache directory"),
  );
  if (!inside(runnerTemp, cacheDirectory, false)) {
    fail("coverage cache directory must stay inside RUNNER_TEMP");
  }
  if (inside(repositoryRoot, cacheDirectory) || inside(cacheDirectory, repositoryRoot)) {
    fail("coverage cache directory and measured repository must not overlap");
  }
  const args = ["prepare", "--repo", repositoryRoot, "--cache-dir", cacheDirectory];
  const subdir = optional(environment.SUBDIR, "subdir");
  if (subdir !== "") args.push("--subdir", canonicalRelative(subdir, "subdir"));
  return args;
}

/**
 * Setup-phase provider staging. A CLI failure here is a WARNING, not a job failure: a missing
 * provider is a modeled measurement outcome (`Layer 0: cannot-attest`) under the advisory
 * default, and denying the whole measurement over a registry hiccup would delete real evidence.
 * Boundary validation failures above still throw and fail the job — those are trust errors.
 */
export function prepareCoverage(environment = process.env) {
  const args = buildPrepareArguments(environment);
  const cli = realpathSync(required(environment.ABLOH_CLI_PATH, "installed CLI path"));
  const prefix = realpathSync(required(environment.ABLOH_CLI_PREFIX, "installed CLI prefix"));
  if (!inside(prefix, cli, false) || !lstatSync(cli).isFile()) {
    fail("Abloh CLI executable must resolve inside the private installation prefix");
  }
  const childEnvironment = { ...environment };
  for (const key of INSTALL_SECRETS) delete childEnvironment[key];
  delete childEnvironment.ABLOH_CLI_PATH;
  delete childEnvironment.ABLOH_CLI_PREFIX;
  delete childEnvironment.MODEL_GATEWAY_URL;
  delete childEnvironment.MODEL_GATEWAY_AUDIENCE;
  const result = spawnSync(cli, args, { env: childEnvironment, stdio: "inherit" });
  if (result.error) throw result.error;
  if ((result.status ?? 2) !== 0) {
    process.stderr.write(
      `abloh prepare exited ${result.status ?? "unknown"}; measurement continues and ` +
      "Layer 0 will record cannot-attest: coverage provider unavailable\n",
    );
  }
  return 0;
}

export async function runAbloh(environment = process.env, fetchImpl = fetch) {
  const cli = realpathSync(required(environment.ABLOH_CLI_PATH, "installed CLI path"));
  const prefix = realpathSync(required(environment.ABLOH_CLI_PREFIX, "installed CLI prefix"));
  if (!inside(prefix, cli, false) || !lstatSync(cli).isFile()) {
    fail("Abloh CLI executable must resolve inside the private installation prefix");
  }
  /*
   * No gateway configured means no model environment, and no OIDC identity minted for one.
   *
   * This used to run unconditionally, which is why a tier-0 repository could not use the Action:
   * every run demanded a gateway, including runs whose whole point is mechanical evidence. The
   * CLI is left to raise the missing-endpoint error if a policy actually names a hosted provider
   * — see the note in validateActionInputs for why this boundary cannot decide that itself.
   */
  const childEnvironment = { ...environment };
  for (const key of INSTALL_SECRETS) delete childEnvironment[key];
  if (optional(environment.MODEL_GATEWAY_URL, "model-gateway-url") !== "") {
    /*
     * The IDENTITY IS NOT MINTED HERE. The endpoint that mints it is passed through instead.
     *
     * A token obtained now is presented minutes later: everything mechanical — baseline, coverage,
     * mutation, per-test attribution — runs before the first model call. A GitHub OIDC token is
     * short-lived, so triage arrived at the gateway with an expired identity, got 401, and the run
     * reported "the provider is unusable (binary missing or auth dead)". The credential is now
     * obtained at the moment it is used.
     *
     * The gateway URL and audience are still validated here, so a misconfigured gateway fails
     * before the suite runs rather than after it.
     */
    const gateway = await validatedModelGatewayTarget(environment);
    childEnvironment.ATTEST_MODEL_ENDPOINT = gateway.gatewayUrl;
    childEnvironment.ATTEST_MODEL_ENDPOINT_ALT = gateway.gatewayUrl;
    childEnvironment.ATTEST_MODEL_AUTH = "bearer";
    childEnvironment.ATTEST_MODEL_OIDC_REQUEST_URL = required(
      environment.ACTIONS_ID_TOKEN_REQUEST_URL,
      "GitHub OIDC request URL",
    );
    childEnvironment.ATTEST_MODEL_OIDC_REQUEST_TOKEN = required(
      environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
      "GitHub OIDC request token",
    );
    childEnvironment.ATTEST_MODEL_OIDC_AUDIENCE = gateway.audience;
  }
  // These are Action orchestration paths, not customer test inputs.
  delete childEnvironment.ABLOH_CLI_PATH;
  delete childEnvironment.ABLOH_CLI_PREFIX;
  delete childEnvironment.ABLOH_OUTPUT_DIR;
  delete childEnvironment.MODEL_GATEWAY_URL;
  delete childEnvironment.MODEL_GATEWAY_AUDIENCE;
  const result = spawnSync(cli, buildRunArguments(environment), {
    env: childEnvironment,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  return result.status ?? 2;
}

export function validateArtifact(environment = process.env) {
  const outputDirectory = realpathSync(required(environment.ABLOH_OUTPUT_DIR, "output directory"));
  const name = required(environment.ABLOH_ARTIFACT_NAME, "artifact name");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(name)) fail("artifact name is unsafe");
  const artifact = join(outputDirectory, name);
  if (!existsSync(artifact)) return null;
  const info = lstatSync(artifact);
  if (info.isSymbolicLink() || !info.isFile()) fail(`${name} must be a regular non-symlink file`);
  const canonical = realpathSync(artifact);
  if (!inside(outputDirectory, canonical, false)) fail(`${name} escaped the output directory`);
  return canonical;
}

/**
 * Post the measured evidence to the control plane, authenticated by a fresh GitHub OIDC identity.
 *
 * Runs as its own step AFTER measurement, so the token is minted once the customer's tests have
 * finished — it never exists while their code is running. It is passed to no child process; the only
 * thing that sees it is this fetch.
 */
export async function uploadEvidence(environment = process.env, fetchImpl = fetch) {
  const handoffUrl = credentialFreeHttps(environment.HANDOFF_URL, "handoff-url");
  const audience = required(environment.HANDOFF_AUDIENCE, "handoff-audience");
  if (audience.length > 512) fail("handoff-audience is too long");

  /* The same proof the validate-artifact step performs: a regular file, not a symlink, inside the
     run's own output directory. Reused rather than re-implemented so both agree on what counts. */
  const resultsPath = validateArtifact({
    ...environment,
    ABLOH_ARTIFACT_NAME: "attest-results.json",
  });
  if (resultsPath === null) fail("no completed measurement artifact to upload");

  const { buildStructuralHandoff, contextFromEnvironment } = await import("./build-handoff.mjs");
  const evidence = JSON.parse(readFileSync(resultsPath, "utf8"));
  /* Tier-2 sidecars ride along when the run produced them; buildStructuralHandoff drops them below
     tier 2, so the tier decision stays in one place. */
  const outputDirectory = dirname(resultsPath);
  const sidecars = {
    rationales: readOptionalFile(join(outputDirectory, "attest-rationales.json")),
    fixProofs: readOptionalFile(join(outputDirectory, "attest-fix-proofs.json")),
    /* Structural, so these ride along at every tier — buildStructuralHandoff drops the two above
       below tier 2 and keeps these, so the tier decision stays in that single place.

       Coverage is sent VERBATIM even though its absolute runner paths are not what gets stored: the
       control plane checks these exact bytes against `rawCoverageDigest` first and rewrites the
       paths afterwards. Normalizing here would produce bytes that match no commitment. */
    patchRevert: readOptionalFile(join(outputDirectory, "attest-patch-revert.json")),
    coverage: readOptionalFile(join(outputDirectory, "attest-raw-coverage.json")),
    /* The REDACTED report, never `attest-raw-report.json`. That file embeds the customer's source
       and stays on this runner; this one is the source-free rewrite the CLI wrote and committed to.
       buildStructuralHandoff withholds it below tier 1. */
    mutationRedacted: readOptionalFile(join(outputDirectory, "attest-mutation-redacted.json")),
  };
  /*
   * The artifact digest is computed HERE, over the exact bytes just read.
   *
   * contextFromEnvironment takes it from ABLOH_LOCAL_ARTIFACT_DIGEST, which the reusable workflow sets
   * from a shell `sha256sum`. This step has no such shell local, and an absent value becomes "" —
   * which the control plane refuses, so the omission would have failed every upload rather than
   * shipping a wrong digest. Computed from the file already in hand instead.
   */
  const artifactDigest = `sha256:${createHash("sha256").update(readFileSync(resultsPath)).digest("hex")}`;
  const envelope = buildStructuralHandoff(
    evidence,
    contextFromEnvironment({ ...environment, ABLOH_LOCAL_ARTIFACT_DIGEST: artifactDigest }),
    sidecars,
  );

  const token = await mintGitHubIdentity(environment, audience, "evidence handoff", fetchImpl);
  let response;
  try {
    response = await fetchImpl(handoffUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(envelope),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    fail("the evidence upload could not reach the control plane");
  }
  if (!response.ok) {
    /* The status is disclosed and the body is NOT: it is a remote string, and echoing it into a job
       log is how a service's internals end up in a customer's public build output. */
    fail(`the control plane refused the evidence upload (HTTP ${response.status})`);
  }
  return 0;
}

/** A sidecar's raw bytes, or undefined when the run produced none. Bounded like the artifact. */
function readOptionalFile(path) {
  try {
    const bytes = statSync(path).size;
    if (bytes < 1 || bytes > 16 * 1024 * 1024) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

async function main(environment = process.env) {
  const command = process.argv[2];
  if (command === "preflight") {
    const result = preflight(environment);
    appendOutput(environment.GITHUB_OUTPUT, {
      base: result.effectiveBase,
      head: result.expectedHead,
      "repository-root": result.repositoryRoot,
      "output-dir": result.outputDirectory,
      "baseline-dir": result.baselineDirectory,
      "coverage-cache-dir": result.coverageCacheDirectory,
    });
    return 0;
  }
  if (command === "install-cli") {
    const result = installCli(environment);
    appendOutput(environment.GITHUB_OUTPUT, { path: result.cli, prefix: result.prefix });
    return 0;
  }
  if (command === "prepare") return prepareCoverage(environment);
  if (command === "run") return runAbloh(environment);
  if (command === "upload") return await uploadEvidence(environment);
  if (command === "validate-artifact") {
    const artifact = validateArtifact(environment);
    if (artifact !== null) process.stdout.write(artifact);
    return 0;
  }
  fail("expected preflight, install-cli, prepare, run, upload, or validate-artifact");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    process.exitCode = await main(process.env);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  }
}
