import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertSupportedNodeVersion,
  buildPrepareArguments,
  buildRunArguments,
  DEFAULT_CLI_SPEC,
  parsePackageSpecs,
  runAbloh,
  validateActionInputs,
  validateArtifact,
} from "./action-boundary.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BOUNDARY = join(HERE, "action-boundary.mjs");
const ACTION = join(HERE, "action.yml");
const ACTUAL_GIT = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
const ACTUAL_NODE = process.execPath;
const ACTUAL_NPM = execFileSync("which", ["npm"], { encoding: "utf8" }).trim();

function temporary(label) {
  return mkdtempSync(join(tmpdir(), `abloh-action-${label}-`));
}

function writeExecutable(path, source) {
  writeFileSync(path, source, { mode: 0o755 });
  chmodSync(path, 0o755);
}

function toolPath(root, { docker = true, npm = ACTUAL_NPM } = {}) {
  const bin = join(root, "tools");
  mkdirSync(bin, { recursive: true });
  symlinkSync(ACTUAL_GIT, join(bin, "git"));
  symlinkSync(ACTUAL_NODE, join(bin, "node"));
  symlinkSync(npm, join(bin, "npm"));
  if (docker) writeExecutable(join(bin, "docker"), "#!/bin/sh\nexit 0\n");
  return bin;
}

function git(repo, ...args) {
  return execFileSync(ACTUAL_GIT, ["-C", repo, ...args], { encoding: "utf8" }).trim();
}

function repository(root, kind = "javascript") {
  const workspace = join(root, "workspace");
  const repo = join(workspace, "repo with space");
  mkdirSync(repo, { recursive: true });
  git(repo, "init", "-q");
  git(repo, "config", "user.name", "Abloh Test");
  git(repo, "config", "user.email", "test@abloh.invalid");
  if (kind === "python") {
    writeFileSync(join(repo, "pyproject.toml"), "[project]\nname='demo'\nversion='0.0.0'\n");
  } else {
    writeFileSync(join(repo, "package.json"), '{"name":"demo","scripts":{"test":"node --test"}}\n');
  }
  writeFileSync(join(repo, "subject.txt"), "base\n");
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "base");
  const base = git(repo, "rev-parse", "HEAD");
  writeFileSync(join(repo, "subject.txt"), "head\n");
  git(repo, "add", "subject.txt");
  git(repo, "commit", "-qm", "head");
  const head = git(repo, "rev-parse", "HEAD");
  return { workspace, repo, base, head };
}

function preflightEnvironment(root, fixture, extra = {}) {
  const output = join(root, "github-output");
  writeFileSync(output, "", { mode: 0o600 });
  const runnerTemp = join(root, "runner-temp");
  mkdirSync(runnerTemp);
  return {
    ...process.env,
    PATH: toolPath(root),
    GITHUB_ACTION_PATH: HERE,
    GITHUB_OUTPUT: output,
    GITHUB_WORKSPACE: fixture.workspace,
    RUNNER_TEMP: runnerTemp,
    REPO_PATH: "repo with space",
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_SHA_VALUE: fixture.head,
    PR_HEAD_SHA: fixture.head,
    PR_BASE_SHA: fixture.base,
    DECLARED_BASE: fixture.base,
    GITHUB_RUN_ID: "1234",
    GITHUB_RUN_ATTEMPT: "1",
    MODEL_GATEWAY_URL: "https://api.abloh.example/api/v1/model/chat/completions",
    MODEL_GATEWAY_AUDIENCE: "https://api.abloh.example/model",
    ...extra,
  };
}

function execute(command, environment) {
  return spawnSync(process.execPath, [BOUNDARY, command], {
    encoding: "utf8",
    env: environment,
  });
}

function outputFields(path) {
  return Object.fromEntries(
    readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
  );
}

test("preflight binds the exact PR head/base and creates private staging outside the checkout", () => {
  const root = temporary("preflight");
  const fixture = repository(root);
  const environment = preflightEnvironment(root, fixture);
  const result = execute("preflight", environment);
  assert.equal(result.status, 0, result.stderr);
  const fields = outputFields(environment.GITHUB_OUTPUT);
  assert.equal(fields.base, fixture.base);
  assert.equal(fields.head, fixture.head);
  assert.equal(fields["repository-root"], realpathSync(fixture.repo));
  assert.match(fields["output-dir"], /runner-temp\/abloh\/1234-1$/u);
  assert.match(fields["baseline-dir"], /runner-temp\/abloh-state\/1234-1\/baseline-history$/u);
  assert.match(fields["coverage-cache-dir"], /runner-temp\/abloh-state\/1234-1\/coverage-providers-fresh$/u);
  assert.equal(lstatSync(fields["output-dir"]).isSymbolicLink(), false);
  assert.equal(git(fixture.repo, "status", "--porcelain"), "");
});

test("preflight refuses synthetic target events, head/base substitution, and missing Docker", async (t) => {
  await t.test("pull_request_target", () => {
    const root = temporary("target-event");
    const fixture = repository(root);
    const result = execute("preflight", preflightEnvironment(root, fixture, {
      GITHUB_EVENT_NAME: "pull_request_target",
    }));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /pull_request_target is unsafe/u);
  });
  await t.test("wrong head", () => {
    const root = temporary("wrong-head");
    const fixture = repository(root);
    const result = execute("preflight", preflightEnvironment(root, fixture, {
      PR_HEAD_SHA: fixture.base,
    }));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /exact pull-request head required/u);
  });
  await t.test("wrong declared base", () => {
    const root = temporary("wrong-base");
    const fixture = repository(root);
    const result = execute("preflight", preflightEnvironment(root, fixture, {
      DECLARED_BASE: fixture.head,
    }));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /pull-request base/u);
  });
  await t.test("missing Docker", () => {
    const root = temporary("missing-docker");
    const fixture = repository(root);
    const environment = preflightEnvironment(root, fixture);
    environment.PATH = toolPath(join(root, "without-docker"), { docker: false });
    const result = execute("preflight", environment);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /docker must be installed/u);
  });
  await t.test("missing npm", () => {
    const root = temporary("missing-npm");
    const fixture = repository(root);
    const environment = preflightEnvironment(root, fixture);
    unlinkSync(join(environment.PATH, "npm"));
    const result = execute("preflight", environment);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /npm must be installed/u);
  });
  await t.test("unreachable Docker daemon", () => {
    const root = temporary("dead-docker");
    const fixture = repository(root);
    const environment = preflightEnvironment(root, fixture);
    writeExecutable(join(environment.PATH, "docker"), "#!/bin/sh\nexit 1\n");
    const result = execute("preflight", environment);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /reachable daemon/u);
  });
});

test("preflight refuses hostile repository paths, symlink escapes, and occupied output staging", async (t) => {
  await t.test("lexical escape", () => {
    const root = temporary("repo-escape");
    const fixture = repository(root);
    const result = execute("preflight", preflightEnvironment(root, fixture, { REPO_PATH: "../outside" }));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /canonical relative POSIX path/u);
  });
  await t.test("symlink escape", () => {
    const root = temporary("repo-link");
    const fixture = repository(root);
    const outside = join(root, "outside");
    mkdirSync(outside);
    symlinkSync(outside, join(fixture.workspace, "linked"));
    const result = execute("preflight", preflightEnvironment(root, fixture, { REPO_PATH: "linked" }));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /resolves outside/u);
  });
  await t.test("control characters", () => {
    const root = temporary("repo-control");
    const fixture = repository(root);
    const result = execute("preflight", preflightEnvironment(root, fixture, { REPO_PATH: "repo\nwith space" }));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /control-free/u);
  });
  await t.test("pre-created output symlink", () => {
    const root = temporary("output-link");
    const fixture = repository(root);
    const environment = preflightEnvironment(root, fixture);
    mkdirSync(join(environment.RUNNER_TEMP, "abloh"));
    symlinkSync(fixture.repo, join(environment.RUNNER_TEMP, "abloh", "1234-1"));
    const result = execute("preflight", environment);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /staging leaf already exists/u);
  });
  await t.test("runner temporary directory inside checkout", () => {
    const root = temporary("output-overlap");
    const fixture = repository(root);
    const environment = preflightEnvironment(root, fixture);
    environment.RUNNER_TEMP = join(fixture.repo, ".runner-temp");
    mkdirSync(environment.RUNNER_TEMP);
    const result = execute("preflight", environment);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /must not overlap the measured repository/u);
  });
});

function fakeCli(root) {
  const prefix = join(root, "runner-temp", "abloh-cli", "1234-1");
  mkdirSync(join(prefix, "bin"), { recursive: true });
  mkdirSync(join(prefix, "lib"), { recursive: true });
  const target = join(prefix, "lib", "cli.mjs");
  writeExecutable(target, `#!${process.execPath}\nimport { writeFileSync } from 'node:fs';\nwriteFileSync(process.env.ACTION_RECORD_PATH, JSON.stringify({ argv: process.argv.slice(2), env: { model: process.env.ATTEST_MODEL_API_KEY, modelAlt: process.env.ATTEST_MODEL_API_KEY_ALT, oidcUrl: process.env.ATTEST_MODEL_OIDC_REQUEST_URL, oidcAudience: process.env.ATTEST_MODEL_OIDC_AUDIENCE, endpoint: process.env.ATTEST_MODEL_ENDPOINT, auth: process.env.ATTEST_MODEL_AUTH, github: process.env.GITHUB_TOKEN, api: process.env.API_TOKEN, output: process.env.ABLOH_OUTPUT_DIR } }));\n`);
  symlinkSync("../lib/cli.mjs", join(prefix, "bin", "abloh"));
  return { cli: join(prefix, "bin", "abloh"), prefix };
}

test("the executable run boundary routes JS and Python identically without shell interpretation", async (t) => {
  for (const kind of ["javascript", "python"]) {
    await t.test(kind, async () => {
      const root = temporary(`run-${kind}`);
      const fixture = repository(root, kind);
      const environment = preflightEnvironment(root, fixture);
      assert.equal(execute("preflight", environment).status, 0);
      const fields = outputFields(environment.GITHUB_OUTPUT);
      const installed = fakeCli(root);
      const record = join(root, "invocation.json");
      const pwned = join(root, "pwned");
      const testCommand = `node --test 'literal;touch ${pwned}'`;
      const oidc = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhYmxvaCJ9.signature";
      const runEnvironment = {
        ...process.env,
        RUNNER_TEMP: environment.RUNNER_TEMP,
        REPOSITORY_ROOT: fields["repository-root"],
        BASE: fixture.base,
        HEAD_SHA: fixture.head,
        TIER: "1",
        SUBDIR: "packages/demo",
        POLICY: "config/abloh.yml",
        ENVIRONMENT_IMAGE: `registry.example:5000/node@sha256:${"a".repeat(64)}`,
        TEST_COMMAND: testCommand,
        SEED: "b".repeat(32),
        ABLOH_OUTPUT_DIR: fields["output-dir"],
        ABLOH_CLI_PATH: installed.cli,
        ABLOH_CLI_PREFIX: installed.prefix,
        ACTION_RECORD_PATH: record,
        MODEL_GATEWAY_URL: "https://api.abloh.example/api/v1/model/chat/completions",
        MODEL_GATEWAY_AUDIENCE: "https://api.abloh.example/model",
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.actions.githubusercontent.com/oidc?x=1",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "github-oidc-request-secret",
        ATTEST_MODEL_API_KEY: undefined,
        ATTEST_MODEL_API_KEY_ALT: undefined,
        ANTHROPIC_API_KEY: undefined,
        OPENAI_API_KEY: undefined,
        GITHUB_TOKEN: "github-secret-sentinel",
        API_TOKEN: "api-secret-sentinel",
      };
      const requested = [];
      const status = await runAbloh(runEnvironment, async (url, options) => {
        requested.push({ url: String(url), authorization: options?.headers?.authorization });
        return new Response(JSON.stringify({ value: oidc }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      });
      assert.equal(status, 0);
      /* NOTHING is minted here any more. A token obtained now is presented minutes later — after
         baseline, coverage, mutation and per-test attribution — and a short-lived GitHub identity
         has expired by then. Observed on a real tier-2 run: the gateway answered 401 and the CLI
         reported "the provider is unusable (binary missing or auth dead)". The CLI is handed the
         MINTING ENDPOINT and obtains the credential when it makes the call. */
      assert.deepEqual(requested, [], "the run boundary must not mint an identity it will not use");
      const invocation = JSON.parse(readFileSync(record, "utf8"));
      assert.equal(invocation.argv.includes("--lang"), false, "language routing belongs to the CLI");
      assert.equal(invocation.argv[invocation.argv.indexOf("--test-command") + 1], testCommand);
      assert.equal(invocation.argv[invocation.argv.indexOf("--repo") + 1], realpathSync(fixture.repo));
      assert.equal(invocation.env.model, undefined, "no pre-minted key is handed to the CLI");
      assert.equal(
        invocation.env.oidcUrl,
        "https://token.actions.githubusercontent.com/oidc?x=1",
        "the CLI receives the endpoint that mints the identity, not the identity",
      );
      assert.equal(invocation.env.oidcAudience, "https://api.abloh.example/model");
      assert.equal(invocation.env.modelAlt, undefined, "nor to the alternate slot");
      assert.equal(invocation.env.endpoint, "https://api.abloh.example/api/v1/model/chat/completions");
      assert.equal(invocation.env.auth, "bearer");
      assert.equal(invocation.env.github, undefined);
      assert.equal(invocation.env.api, undefined);
      assert.equal(invocation.env.output, undefined, "customer tests do not receive Action staging paths");
      assert.equal(readFileSync(environment.GITHUB_OUTPUT, "utf8").includes("secret-sentinel"), false);
      assert.equal(git(fixture.repo, "status", "--porcelain"), "");
      assert.throws(() => readFileSync(pwned), /ENOENT/u);
    });
  }
});

test("the customer Action refuses direct model-provider credentials", async () => {
  const root = temporary("direct-model-secret");
  const fixture = repository(root);
  const environment = preflightEnvironment(root, fixture);
  assert.equal(execute("preflight", environment).status, 0);
  const fields = outputFields(environment.GITHUB_OUTPUT);
  const installed = fakeCli(root);
  await assert.rejects(
    runAbloh({
      ...environment,
      REPOSITORY_ROOT: fields["repository-root"],
      BASE: fixture.base,
      HEAD_SHA: fixture.head,
      ABLOH_OUTPUT_DIR: fields["output-dir"],
      ABLOH_CLI_PATH: installed.cli,
      ABLOH_CLI_PREFIX: installed.prefix,
      ATTEST_MODEL_API_KEY: "raw-provider-secret",
    }),
    /must not be supplied to the customer Action/u,
  );
});

test("run argument admission rejects path, image, seed, and staging attacks before the CLI", async (t) => {
  const root = temporary("run-admission");
  const fixture = repository(root);
  const runnerTemp = join(root, "runner-temp");
  const output = join(runnerTemp, "abloh", "1-1");
  mkdirSync(output, { recursive: true });
  const common = {
    REPOSITORY_ROOT: fixture.repo,
    BASE: fixture.base,
    HEAD_SHA: fixture.head,
    TIER: "1",
    RUNNER_TEMP: runnerTemp,
    ABLOH_OUTPUT_DIR: output,
  };
  await t.test("subdir escape", () => assert.throws(
    () => buildRunArguments({ ...common, SUBDIR: "../escape" }),
    /canonical relative/u,
  ));
  await t.test("policy escape", () => assert.throws(
    () => buildRunArguments({ ...common, POLICY: "/tmp/abloh.yml" }),
    /canonical relative/u,
  ));
  await t.test("mutable image", () => assert.throws(
    () => buildRunArguments({ ...common, ENVIRONMENT_IMAGE: "node:24" }),
    /immutable/u,
  ));
  await t.test("seed injection", () => assert.throws(
    () => buildRunArguments({ ...common, SEED: "a; touch x" }),
    /hexadecimal/u,
  ));
  await t.test("checkout output", () => assert.throws(
    () => buildRunArguments({ ...common, ABLOH_OUTPUT_DIR: fixture.repo }),
    /must stay inside RUNNER_TEMP/u,
  ));
});

test("pull-request run arguments contain no caller-controlled measurement override", async (t) => {
  const root = temporary("trusted-pr-argv");
  const fixture = repository(root);
  const runnerTemp = join(root, "runner-temp");
  const output = join(runnerTemp, "abloh", "1-1");
  mkdirSync(output, { recursive: true });
  const common = {
    GITHUB_EVENT_NAME: "pull_request",
    REPOSITORY_ROOT: fixture.repo,
    BASE: fixture.base,
    HEAD_SHA: fixture.head,
    TIER: "",
    SUBDIR: "",
    POLICY: "",
    ENVIRONMENT_IMAGE: "",
    TEST_COMMAND: "",
    SEED: "",
    RUNNER_TEMP: runnerTemp,
    ABLOH_OUTPUT_DIR: output,
  };
  const args = buildRunArguments(common);
  for (const flag of ["--tier", "--subdir", "--policy", "--environment-image", "--test-command", "--seed"]) {
    assert.equal(args.includes(flag), false, `${flag} must come only from trusted merge-base policy`);
  }
  assert.deepEqual(args.slice(0, 7), [
    "run", "--repo", realpathSync(fixture.repo), "--base", fixture.base, "--head", fixture.head,
  ]);

  const attacks = [
    ["TIER", "0", "tier"],
    ["SUBDIR", "packages/weak", "subdir"],
    ["POLICY", "weak.yml", "policy"],
    ["ENVIRONMENT_IMAGE", `attacker.invalid/node@sha256:${"a".repeat(64)}`, "environment-image"],
    ["TEST_COMMAND", "node fake-green-suite.mjs", "test-command"],
    ["SEED", "a", "seed"],
  ];
  for (const [name, value, label] of attacks) {
    await t.test(label, () => assert.throws(
      () => buildRunArguments({ ...common, [name]: value }),
      new RegExp(`trusted merge-base abloh\\.yml.*${label}`, "u"),
    ));
  }
});

test("all public Action inputs are admitted before the expensive run starts", () => {
  assert.doesNotThrow(() => validateActionInputs({
    TIER: "1",
    UPLOAD: "false",
    SUBDIR: "packages/demo app",
    POLICY: "config/abloh.yml",
    ENVIRONMENT_IMAGE: `registry.example/node@sha256:${"a".repeat(64)}`,
    TEST_COMMAND: "node --test 'test file.mjs'",
    SEED: "A",
    MODEL_GATEWAY_URL: "https://api.abloh.example/api/v1/model/chat/completions",
    MODEL_GATEWAY_AUDIENCE: "https://api.abloh.example/model",
  }));
  assert.throws(() => validateActionInputs({ TIER: "9" }), /tier must be 0, 1, or 2/u);
  assert.throws(() => validateActionInputs({ UPLOAD: "yes" }), /upload must be true or false/u);
  /* UPLOAD IS NOW ADMITTED. It used to be refused as "token-bearing", which was true of a shared
     secret and untrue of the GitHub OIDC identity the upload step actually mints — scoped to one
     audience, valid for minutes, and authorizing only "post evidence about this repo at this commit",
     which a job running the customer's tests can do anyway. The limit that remains is the GRADE: the
     control plane records no artifact digest for this path, so it can never read `service-verified`. */
  assert.doesNotThrow(() => validateActionInputs({
    UPLOAD: "true",
    MODEL_GATEWAY_URL: "https://api.abloh.example/api/v1/model/chat/completions",
    MODEL_GATEWAY_AUDIENCE: "https://api.abloh.example/model",
  }));
  assert.throws(() => validateActionInputs({ PR_COMMENT: "cli" }), /PR reporting is unavailable/u);
  assert.throws(() => validateActionInputs({ SUBDIR: "--uncommitted" }), /canonical relative/u);
  assert.throws(() => validateActionInputs({ POLICY: "config/../abloh.yml" }), /canonical relative/u);
  assert.throws(() => validateActionInputs({ TEST_COMMAND: "--uncommitted" }), /must begin with an executable/u);
});

test("pull-request preflight refuses every measurement override before repository execution", async (t) => {
  const attacks = [
    ["TIER", "1", "tier"],
    ["SUBDIR", "packages/demo", "subdir"],
    ["POLICY", "config/abloh.yml", "policy"],
    ["ENVIRONMENT_IMAGE", `attacker.invalid/node@sha256:${"a".repeat(64)}`, "environment-image"],
    ["TEST_COMMAND", "node fake-green-suite.mjs", "test-command"],
    ["SEED", "a", "seed"],
  ];
  for (const [name, value, label] of attacks) {
    await t.test(label, () => {
      const root = temporary(`trusted-pr-preflight-${label}`);
      const fixture = repository(root);
      const result = execute("preflight", preflightEnvironment(root, fixture, { [name]: value }));
      assert.equal(result.status, 2);
      assert.match(result.stderr, /trusted merge-base abloh\.yml/u);
      assert.match(result.stderr, new RegExp(label, "u"));
    });
  }
});

test("the Action enforces the CLI's Node >=20.6 runtime boundary", () => {
  assert.doesNotThrow(() => assertSupportedNodeVersion("20.6.0"));
  assert.doesNotThrow(() => assertSupportedNodeVersion("24.18.0"));
  assert.throws(() => assertSupportedNodeVersion("20.5.1"), /Node >=20\.6/u);
  assert.throws(() => assertSupportedNodeVersion("18.20.8"), /Node >=20\.6/u);
});

test("CLI package specs are argument data and the executable must stay under its private prefix", () => {
  assert.deepEqual(parsePackageSpecs("one.tgz https://example.invalid/two.tgz;touch-pwned"), [
    "one.tgz",
    "https://example.invalid/two.tgz;touch-pwned",
  ]);
  assert.throws(() => parsePackageSpecs("--force"), /unsafe package spec/u);
});

/*
 * NOTHING TO PACK, FOR THE FIRST TIME.
 *
 * `cli-tarball` was required because no part of Abloh was on npm: a caller had to pack the CLI and
 * its six workspace dependencies and pass all seven paths, which is why our own e2e repository was
 * the only one that could run this action. With @abloh/cli published, absent means "install the
 * release".
 */
test("an absent cli-tarball installs the published release, pinned", () => {
  assert.deepEqual(parsePackageSpecs(undefined), [DEFAULT_CLI_SPEC]);
  assert.deepEqual(parsePackageSpecs(""), [DEFAULT_CLI_SPEC]);
  assert.deepEqual(parsePackageSpecs("   "), [DEFAULT_CLI_SPEC]);
  /* Pinned, never `latest`: a caller who pinned this action by SHA has already chosen which Abloh
     they run, and resolving a floating tag would change that under them. */
  assert.match(DEFAULT_CLI_SPEC, /^@abloh\/cli@\d+\.\d+\.\d+$/u);
});

test("an explicit cli-tarball still wins, for a build that is not on the registry", () => {
  assert.deepEqual(parsePackageSpecs("./abloh-cli-0.1.0.tgz ./abloh-core-0.1.0.tgz"), [
    "./abloh-cli-0.1.0.tgz",
    "./abloh-core-0.1.0.tgz",
  ]);
});

test("the executable installer keeps package specs literal and binds the CLI to private staging", () => {
  const root = temporary("install-cli");
  const runnerTemp = join(root, "runner-temp");
  const tools = join(root, "fake-tools");
  mkdirSync(runnerTemp);
  mkdirSync(tools);
  const record = join(root, "npm-argv.txt");
  const environmentRecord = join(root, "npm-environment.txt");
  const pwned = join(root, "pwned");
  writeExecutable(join(tools, "npm"), `#!/bin/sh
set -eu
: > "$ACTION_RECORD_PATH"
printf '%s|%s|%s' "\${ATTEST_MODEL_API_KEY-}" "\${GITHUB_TOKEN-}" "\${npm_config_ignore_scripts-}" > "$ACTION_ENV_RECORD_PATH"
prefix=""
while [ "$#" -gt 0 ]; do
  printf '%s\\n' "$1" >> "$ACTION_RECORD_PATH"
  if [ "$1" = "--prefix" ]; then
    shift
    prefix="$1"
    printf '%s\\n' "$1" >> "$ACTION_RECORD_PATH"
  fi
  shift
done
test -n "$prefix"
mkdir -p "$prefix/bin" "$prefix/lib"
printf '#!/bin/sh\\nexit 0\\n' > "$prefix/lib/abloh"
chmod 755 "$prefix/lib/abloh"
ln -s ../lib/abloh "$prefix/bin/abloh"
`);
  const output = join(root, "github-output");
  writeFileSync(output, "");
  const hostileSpec = `https://example.invalid/cli.tgz;touch-${pwned}`;
  const result = execute("install-cli", {
    ...process.env,
    PATH: `${tools}:/usr/bin:/bin`,
    RUNNER_TEMP: runnerTemp,
    GITHUB_RUN_ID: "99",
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_OUTPUT: output,
    CLI_TARBALL: `core.tgz ${hostileSpec}`,
    ACTION_RECORD_PATH: record,
    ACTION_ENV_RECORD_PATH: environmentRecord,
    ATTEST_MODEL_API_KEY: "model-install-secret",
    GITHUB_TOKEN: "github-install-secret",
  });
  assert.equal(result.status, 0, result.stderr);
  const fields = outputFields(output);
  assert.equal(realpathSync(fields.path).startsWith(`${realpathSync(fields.prefix)}/`), true);
  const argv = readFileSync(record, "utf8").trim().split("\n");
  assert.deepEqual(argv.slice(0, 9), [
    "install",
    "-g",
    "--prefix",
    fields.prefix,
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--",
    "core.tgz",
  ]);
  assert.equal(argv.at(-1), hostileSpec);
  assert.equal(readFileSync(environmentRecord, "utf8"), "||true");
  assert.throws(() => readFileSync(pwned), /ENOENT/u);
});

test("artifact boundary rejects symlinks", () => {
  const root = temporary("artifact");
  const output = join(root, "output");
  mkdirSync(output);
  writeFileSync(join(output, "attest-results.json"), "{}\n");
  assert.equal(
    validateArtifact({ ABLOH_OUTPUT_DIR: output, ABLOH_ARTIFACT_NAME: "attest-results.json" }),
    join(realpathSync(output), "attest-results.json"),
  );
  symlinkSync("attest-results.json", join(output, "linked.json"));
  assert.throws(
    () => validateArtifact({ ABLOH_OUTPUT_DIR: output, ABLOH_ARTIFACT_NAME: "linked.json" }),
    /regular non-symlink/u,
  );
});

test("the composite Action uses the executable boundary and never reconstructs customer setup", () => {
  const source = readFileSync(ACTION, "utf8");
  for (const command of ["preflight", "install-cli", "run", "validate-artifact", "upload"]) {
    assert.match(source, new RegExp(`action-boundary\\.mjs[\"']? ${command}`, "u"));
  }
  assert.doesNotMatch(source, /actions\/checkout@/u);
  assert.doesNotMatch(source, /(?:npm ci|pnpm install|yarn install|pip install|poetry install)/u);
  assert.match(source, /steps\.environment_preflight\.outputs\.output-dir/u);
  assert.match(source, /steps\.environment_preflight\.outputs\.head/u);
  assert.match(source, /steps\.environment_preflight\.outputs\.base/u);
  assert.match(source, /steps\.artifact_state\.outputs\.complete == 'true'/u);
  assert.match(source, /GITHUB_EVENT_NAME: \$\{\{ github\.event_name \}\}/u);
  assert.doesNotMatch(source, /(?:GITHUB_TOKEN|API_TOKEN|github-token|api-token|post-report|prepare-upload\.mjs|upload-url)/u);
  assert.doesNotMatch(source, /inputs\.(?:upload|pr-comment)/u);
  /* The upload step exists and is OIDC-only: it names the handoff inputs and carries no long-lived
     credential. The doesNotMatch above already forbids GITHUB_TOKEN/API_TOKEN anywhere in the file, so
     the two together say "uploads, but never with a shared secret". */
  assert.match(source, /HANDOFF_URL: \$\{\{ inputs\.handoff-url \}\}/u);
  assert.match(source, /HANDOFF_AUDIENCE: \$\{\{ inputs\.handoff-audience \}\}/u);
  assert.doesNotMatch(source, /Restore version-bound coverage adapters/u);
  assert.doesNotMatch(source, /Save version-bound coverage adapters/u);
  assert.doesNotMatch(source, /\/tmp\/attest-post-report/u);
});

test("prepare builds a trusted argv, refuses PR overrides, and soft-fails CLI errors", async (t) => {
  await t.test("argv shape with the preflight-minted cache dir", () => {
    const root = temporary("prepare-argv");
    const runnerTemp = join(root, "runner-temp");
    const cacheDir = join(runnerTemp, "abloh-state", "1-1", "coverage-providers-fresh");
    mkdirSync(cacheDir, { recursive: true });
    const repo = join(root, "repo");
    mkdirSync(repo, { recursive: true });
    const args = buildPrepareArguments({
      GITHUB_EVENT_NAME: "push",
      REPOSITORY_ROOT: repo,
      RUNNER_TEMP: runnerTemp,
      ABLOH_COVERAGE_PROVIDER_CACHE_DIR: cacheDir,
      SUBDIR: "packages/api",
    });
    assert.deepEqual(args, [
      "prepare",
      "--repo", realpathSync(repo),
      "--cache-dir", realpathSync(cacheDir),
      "--subdir", "packages/api",
    ]);
  });

  await t.test("pull_request events refuse a caller-controlled subdir", () => {
    const root = temporary("prepare-pr");
    const runnerTemp = join(root, "runner-temp");
    const cacheDir = join(runnerTemp, "cache");
    mkdirSync(cacheDir, { recursive: true });
    const repo = join(root, "repo");
    mkdirSync(repo, { recursive: true });
    assert.throws(() => buildPrepareArguments({
      GITHUB_EVENT_NAME: "pull_request",
      REPOSITORY_ROOT: repo,
      RUNNER_TEMP: runnerTemp,
      ABLOH_COVERAGE_PROVIDER_CACHE_DIR: cacheDir,
      SUBDIR: "packages/api",
    }), /pull_request runs must derive/u);
  });

  await t.test("a cache dir outside RUNNER_TEMP or overlapping the repo is refused", () => {
    const root = temporary("prepare-escape");
    const runnerTemp = join(root, "runner-temp");
    mkdirSync(runnerTemp, { recursive: true });
    const repo = join(root, "repo");
    mkdirSync(join(repo, "cache"), { recursive: true });
    const outside = join(root, "elsewhere");
    mkdirSync(outside, { recursive: true });
    for (const bad of [outside, join(repo, "cache")]) {
      assert.throws(() => buildPrepareArguments({
        GITHUB_EVENT_NAME: "push",
        REPOSITORY_ROOT: repo,
        RUNNER_TEMP: runnerTemp,
        ABLOH_COVERAGE_PROVIDER_CACHE_DIR: bad,
      }), /coverage cache/u);
    }
  });

  await t.test("a failing CLI prepare warns and exits 0; boundary errors still fail", async () => {
    const root = temporary("prepare-soft");
    const runnerTemp = join(root, "runner-temp");
    const cacheDir = join(runnerTemp, "abloh-state", "1-1", "coverage-providers-fresh");
    mkdirSync(cacheDir, { recursive: true });
    const repo = join(root, "repo");
    mkdirSync(repo, { recursive: true });
    const { cli, prefix } = fakeCli(root);
    writeExecutable(join(prefix, "lib", "cli.mjs"), `#!${process.execPath}\nprocess.exit(2);\n`);
    const environment = {
      PATH: process.env.PATH,
      GITHUB_EVENT_NAME: "push",
      REPOSITORY_ROOT: repo,
      RUNNER_TEMP: runnerTemp,
      ABLOH_COVERAGE_PROVIDER_CACHE_DIR: cacheDir,
      ABLOH_CLI_PATH: cli,
      ABLOH_CLI_PREFIX: prefix,
    };
    const soft = execute("prepare", environment);
    assert.equal(soft.status, 0, soft.stderr);
    assert.match(soft.stderr, /Layer 0 will record cannot-attest/u);

    const broken = execute("prepare", { ...environment, ABLOH_COVERAGE_PROVIDER_CACHE_DIR: join(root, "elsewhere2") });
    assert.equal(broken.status, 2, "boundary validation failures must stay fatal");
  });
});

test("a run with no model gateway is admitted, and a supplied one is still validated", () => {
  /* The Action refused to start with "model-gateway-url must be a non-empty control-free string"
     on a real pull request. Nothing mechanical reaches a model — Layer 0, mutation and
     reverse-patch — so that refused runs which would never have called one, and a repository
     wanting structural evidence with no AI could not use the Action at all.

     The boundary cannot decide this by tier: assertTrustedPullRequestInputs refuses a `tier` input
     on a pull_request outright, so the tier is unknown here by design. Absence is carried through
     instead, and a policy naming a hosted provider fails in resolveProvider with a message that
     names the missing variable. */
  const absentRoot = temporary("gateway-absent");
  const noGateway = preflightEnvironment(absentRoot, repository(absentRoot));
  delete noGateway.MODEL_GATEWAY_URL;
  delete noGateway.MODEL_GATEWAY_AUDIENCE;
  assert.equal(execute("preflight", noGateway).status, 0, "a run without a gateway must be admitted");

  /* Supplied means validated, never silently ignored: a malformed value a reader believes is in
     force has to be refused where it is written. */
  const badRoot = temporary("gateway-bad");
  const insecure = preflightEnvironment(badRoot, repository(badRoot), {
    MODEL_GATEWAY_URL: "http://insecure.example/model",
  });
  const rejected = execute("preflight", insecure);
  assert.notEqual(rejected.status, 0, "a non-HTTPS gateway is still refused");
  assert.match(rejected.stderr, /model-gateway-url/u);

  /* A URL without its audience is a half-configured gateway, not an absent one. */
  const audRoot = temporary("gateway-no-aud");
  const noAudience = preflightEnvironment(audRoot, repository(audRoot));
  delete noAudience.MODEL_GATEWAY_AUDIENCE;
  const halfConfigured = execute("preflight", noAudience);
  assert.notEqual(halfConfigured.status, 0, "a gateway URL without an audience is refused");
  assert.match(halfConfigured.stderr, /model-gateway-audience/u);
});

test("a half-configured handoff is refused BEFORE the suite runs, not after it", () => {
  /* handoff-url and handoff-audience were validated for the first time in uploadEvidence — the
     last step. So a missing audience ran the whole measurement first (baseline, coverage,
     mutation, and a reverse-patch lane costing about twice the customer's suite), published it to
     staging, and then threw it away on "handoff-audience must be a non-empty control-free string".
     Observed on a real run: minutes of CI spent to report an input that was knowable before the
     first test executed. */
  const pairRoot = temporary("handoff-pair");
  const halfConfigured = preflightEnvironment(pairRoot, repository(pairRoot), {
    HANDOFF_URL: "https://api.abloh.example/api/v1/orgs/acme/runs/handoff",
  });
  const refused = execute("preflight", halfConfigured);
  assert.notEqual(refused.status, 0, "a handoff URL without its audience must fail at preflight");
  assert.match(refused.stderr, /handoff-audience/u);

  /* No handoff at all is a measure-only run, which is a supported configuration. */
  const noneRoot = temporary("handoff-none");
  const measureOnly = preflightEnvironment(noneRoot, repository(noneRoot));
  assert.equal(execute("preflight", measureOnly).status, 0, "measure-only must still be admitted");

  /* Both supplied is admitted here and re-validated at the upload boundary. */
  const bothRoot = temporary("handoff-both");
  const configured = preflightEnvironment(bothRoot, repository(bothRoot), {
    HANDOFF_URL: "https://api.abloh.example/api/v1/orgs/acme/runs/handoff",
    HANDOFF_AUDIENCE: "abloh-evidence-handoff",
  });
  assert.equal(execute("preflight", configured).status, 0, "a complete handoff pair is admitted");
});
