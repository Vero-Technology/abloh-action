# Abloh — GitHub Action

Composite action that runs `abloh run` after the repository's normal checkout, runtime
setup, dependency installation, code generation, and service setup. It produces
`attest-results/v2` plus a Markdown summary. Advisory is the default: the step fails only
when repository policy enforces a failing gate.

From the prepared repository or package directory, run `abloh init`, review it, and commit the
resulting `abloh.yml` before
enabling the Action. Initialization never installs dependencies or overwrites an existing policy.

Every run applies two distinct checks. Layer 0 records exactly one state for every scoped
changed line and asks whether each executable line was reached by a test. JavaScript and
TypeScript use the detected project runner and a version-matched local, bundled, or Abloh-cached
coverage provider; Python uses the detected project interpreter with `pytest` and either its local
`coverage.py` or Abloh's pinned cached wheel. The selected provider bytes are bound into the
environment contract; restored runner caches never become executable measurement inputs.
Comment-only, blank, and structural-delimiter-only lines are recorded as `not-executable`,
while coverage-excluded executable lines remain visible as `not-instrumented`. A diff with
no executable lines is `not-applicable: no-executable-lines`, never a pass.

Layer 1 asks whether the reached code is protected by tests that detect planted
mutations. When Layer 0 fails, the default `diffCoverage.shortCircuit: false` keeps the
useful mutation run but limits it to covered changed lines. Set
`diffCoverage.shortCircuit: true` in `abloh.yml` for fail-fast behavior.
JavaScript/TypeScript and Python use the same full-scope, covered-only, empty-scope, and
skipped execution semantics.

Coverage and mutation evidence are written next to the JSON artifact as
`attest-raw-coverage.json` and `attest-raw-report.json`, with SHA-256 digests and
provider-correct raw-format metadata in the artifact. Tier 0 performs no LLM calls. There is no
separate Action input for Layer 0 or
short-circuiting: the policy file controls those semantics, and the policy's `enforce`
flag controls advisory versus blocking behavior.

The Action stores JSON, Markdown, rationales, raw evidence, and fix proofs under
`$RUNNER_TEMP/abloh/<run-id>-<attempt>`. Nothing is written into the measured checkout, and the
CLI publishes the staged files only after its workspace-integrity check succeeds. The composite
Action deliberately receives no GitHub or control-plane write token and performs no comment or
upload; those operations require a separate no-checkout privileged job or the Abloh GitHub App.

## Pull-request policy authority

On `pull_request`, Abloh loads `abloh.yml` from the Git merge base and refuses the run when the
measured change introduces, removes, or changes that policy. The Action also refuses non-empty
`tier`, `subdir`, `policy`, `environment-image`, `test-command`, and `seed` inputs, and the CLI
argument vector contains none of those flags. This prevents a pull request from choosing weaker
measurement scope, runtime, tests, sampling, or data-flow settings than the trusted base policy.
Those inputs remain available only for non-PR diagnostic runs.

A model-gateway OIDC identity is deliberately narrower than a model-provider key: it is short-lived,
audience-bound, repository-bound, model-limited, and call-limited. Abloh removes it from every test
process. This is the v1 standard-CI boundary, not a claim that evidence survives an intentionally
malicious PR author running as the same OS user. Tamper-resistant certification remains deferred.
GitHub write operations still belong in a separate no-checkout job or the GitHub App.

## Reproducible checkout binding

The caller checks out `${{ github.event.pull_request.head.sha }}` for pull requests and
falls back to `${{ github.sha }}` for non-PR events, then performs the same setup used by
its normal test job. The action verifies that exact SHA before running. `abloh run`
resolves `--head` and requires it to equal the checked-out `HEAD`; it never labels a
merge-commit measurement as PR-head evidence.

A reproducible run also requires a measured checkout whose execution inputs can be bound:

- no tracked modifications;
- no nonignored untracked files; and
- no tracked symlink that resolves outside the measured repository state.

Contained directory links, missing relative links, and internal link chains are accepted only
because their link targets and resolved bytes are hashed and rechecked after measurement.
Intentional generated inputs should be declared under `environment.generatedFiles`; their bytes,
modes, directory structure, and absence are part of the environment identity. Ignored build
products do not invalidate the checkout. `--uncommitted` is a local-only
diagnostic mode, remains ineligible for certification, and still rejects untracked files
until explicit untracked-file scoping exists. The GitHub Action never enables it.

## Customer-prepared environment contract

By default, the action does not choose a runtime or install project dependencies. It runs after
the customer's normal setup steps in the same GitHub Actions job. This preserves private
registries, generated code, native toolchains, and repository-specific setup without
teaching Abloh how to repair individual repositories.

Repositories that need a clean reproducible setup can declare bounded direct commands instead:

```yaml
environment:
  setupCommands:
    - "pnpm run generate"
  generatedFiles:
    - generated
```

In this mode Abloh creates a detached checkout at the exact measured commit, performs the
package manager's frozen install, runs the declared commands without a shell, hashes the declared
outputs and every resolved tracked-symlink input, and refuses any undeclared write. The source
checkout remains untouched. A setup output may not overlap a changed source file under test.

`abloh.yml` binds the proof environment to an exact test command, immutable test image,
declared local services, required environment-variable names, and selected lock/config
file digests. Abloh runs the untouched HEAD suite once per pull request and stops before all
verification if it is red. The Action restores a customer-side baseline ledger so repeated CI
attempts of that exact commit and environment can identify unstable tests without sending test
names to the control plane. A targeted red-baseline diagnostic is descriptive only and can never
turn the run green. Abloh creates fresh isolated service
state for each HEAD and fault proof and refuses a finding when the environment preflight,
contract identity, or restored-HEAD replay does not match. Secret values are used locally
but never written into the contract artifact.

Coverage runners and providers must already be local to the project or be an exact,
Abloh-bundled provider compatible with the detected runner. Provider invocations use
no-install mode; they never let `npx` download a floating version. Python coverage uses
the selected project interpreter. Direct local CLI use may need one registry-backed
bootstrap of the exact pinned Stryker runtime unless it has been prewarmed, but CI
provider selection never falls back to a floating download.

## SHA-pinned consumption (required — build plan §4.2.7)

This action must be consumed **pinned to a full-length (40-character) commit SHA**, never
a branch or tag:

```yaml
- uses: Vero-Technology/abloh-action@8f14e45fceea167a5a36dedd4bea2543c8b31a7d # pin: full 40-char SHA
  with:
    base: ${{ github.event.pull_request.base.sha }}
```

That is the whole step. The action installs the published `@abloh/cli` — pinned to a version in
`action-boundary.mjs`, never `latest`, because a caller who pinned this action by SHA has already
chosen which Abloh they run.

`cli-tarball` overrides that, and exists for a build the registry does not have: a release
candidate, or a local `pnpm pack`. It takes one or more npm package specs, space-separated, and
npm resolves the CLI's dependencies from the sibling specs in one private runner-temporary prefix:

```yaml
    cli-tarball: >-
      ./vendor/abloh-cli-0.1.2-rc.1.tgz
      ./vendor/abloh-core-0.1.2-rc.1.tgz
```

The resolved SHA is recorded in the evidence as `runner.actionRef`, so the report
identifies exactly which action code produced it. Rollback is the customer
pinning the previous SHA. To update, review the diff between SHAs and move the pin.

## Inputs

| input | required | default | description |
|---|---|---|---|
| `repo-path` | no | `.` | Path to the repository to attest, relative to the workspace. |
| `subdir` | no | — | Non-PR override only. PRs use `target.directory` from trusted base policy and refuse this input; absent both, a workspace-root run auto-selects the package when all changed files fall in exactly one workspace package (`targetSelection: auto-diff` in the artifact). |
| `base` | outside PRs | PR base SHA | Optional on `pull_request`, where the Action derives and verifies the event's exact base SHA. Required on other events. |
| `tier` | no | — | Non-PR override only. PRs use the trusted base policy and refuse this input. |
| `policy` | no | — | Non-PR path override only. PRs resolve `abloh.yml` from the merge base and refuse this input. |
| `environment-image` | no | — | Non-PR immutable-image override only. PRs use trusted policy and refuse this input. |
| `test-command` | no | — | Non-PR direct-command override only. PRs use trusted policy and refuse this input. |
| `seed` | no | — | Non-PR replay override only. PRs mint and record a fresh run seed and refuse this input. |
| `cli-tarball` | **yes, for now** | — | URL(s)/path(s) of the packed CLI tarball (`pnpm pack` output from `apps/cli`) installed into an Action-owned temporary prefix. Space-separate unpublished workspace-dependency tarballs. |

The addresses this Action reports to — the evidence handoff endpoint, the model gateway, and the
OIDC audience each one checks — are **not inputs**. They are constants of the deployment, resolved
by the Action itself, so no workflow names them and no customer has to keep them correct. They were
inputs, and one was wrong in the file the product handed out: the handoff audience read as a URL
where the control plane compares against a fixed string and rejects anything else.

## Example workflow

```yaml
name: Abloh
on: [pull_request]
jobs:
  abloh:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write # short-lived identity for the Abloh model gateway
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 0 # Abloh needs the base ref in history to diff the release range
          persist-credentials: false
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version-file: .nvmrc
          cache: pnpm
      - run: corepack enable
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - uses: Vero-Technology/abloh-action@<40-char-commit-sha>
        with:
          base: ${{ github.event.pull_request.base.sha }}
          cli-tarball: ${{ vars.ATTEST_CLI_TARBALL_URL }}
```

The setup commands above are examples, not commands owned by Abloh. A repository should
use the same pinned runtime, dependency command, generated assets, and local services as
its existing green test job, then invoke Abloh in that job.

Use a normal `pull_request` workflow. The Action refuses `pull_request_target`: that event can
make base-repository secrets available while untrusted pull-request code is being measured. The
composite Action never receives a GitHub write token or a model-provider key. GitHub mints a
short-lived, audience-restricted OIDC identity for the model gateway; the gateway keeps the actual
provider credential server-side. Repository test processes receive neither value.

The customer Action refuses `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and
`ATTEST_MODEL_API_KEY`. Trusted `abloh.yml` still selects the benchmarked model for each task,
while the server independently restricts the repositories, owners, models, and per-run call budget
it will serve. Configure Tier 0 in a separately reviewed base-policy change when intentionally
running the no-model path.

## `cli-tarball` is temporary

There is no published npm package yet, so the action installs the CLI into an Action-owned
runner-temporary prefix from a packed tarball you host (URL) or check in / download in a prior step (path). **At GA this
input is removed**: the published action will run
`npm install -g @abloh/cli@<version>` (exact pinned version baked into the action
at each release).

The composite action's caller-selected `cli-tarball` is a pilot convenience,
not a trusted enforcement path: a caller can select different package bytes.
Use it only for advisory development. GA must bake immutable package identities into the
SHA-pinned composite Action without taking ownership of the customer's project setup.

## Reusable workflow and OIDC handoff (not customer-facing yet)

[`reusable-workflow.template.yml`](./reusable-workflow.template.yml) is retained as an
internal handoff prototype. It must not be published as the normal customer integration:
a job-level reusable workflow cannot inherit setup steps or service state from the
caller's existing test job. The composite action above is the supported design until a
reusable workflow can consume an immutable customer-built environment instead of trying
to reconstruct it.

The intended future invocation remains SHA-pinned:

```yaml
jobs:
  abloh:
    permissions:
      contents: read
      id-token: write
    uses: abloh/abloh/.github/workflows/abloh-attest.yml@<reviewed-40-character-commit-sha>
```

The template uses only SHA-pinned `actions/checkout`, `actions/setup-node`,
`actions/upload-artifact`, and `actions/download-artifact`.
Before publication, Abloh release automation replaces the three literal
`${ABLOH_…}` template placeholders with (1) a fixed JSON array of immutable
HTTPS CLI artifact URLs and their exact SHA-256 digests, (2) the Abloh HTTPS
handoff URL, and (3) the exact OIDC audience. These values are part of the
SHA-pinned reusable workflow and are not `workflow_call` inputs, so a customer
caller cannot redirect its OIDC credential or choose different CLI bytes. The
workflow refuses redirects and verifies every package digest before install.
There is deliberately no demonstration or fallback service URL.

Measurement and customer tests run in a job with `id-token: none`. That job
constructs and locally validates the closed `abloh-ci-handoff/v2` structural
allowlist. In addition to the name-free baseline and bounded structural
findings, v2 carries:

- the exact repository and measured head SHA, plus the bounded changed-line scope;
- one bounded Layer 0 line-state record per scoped changed line;
- the Layer 0 provider, counts, decision, and raw coverage digest/format; and
- mutation execution state plus full, covered-only, or empty mutation scope.

Layer 0 line states must map one-to-one to the changed-line scope, aggregate
counts must match those states, and the coverage provider runner must match the
measured target runner. The upload builder rejects unknown
fields and explicitly excludes source text, replacement snippets, test
identifiers/names, flaky-test sets, prompts/model rationale, candidate code,
raw reports, disclosure prose, and absolute/local repository paths before any
network request. The rich local artifact never leaves the measurement job.
The validated structural JSON is capped at 4 MiB, hashed, and transferred as
the sole short-lived workflow artifact. A separate job with no checkout or
customer-code execution verifies that digest before requesting GitHub OIDC and
uploading the payload. The control plane validates the same closed schema,
count bounds, tenant/OIDC binding, SHA binding, and included finding count
before accepting it.

The handoff job itself is a real no-checkout separation: it has `contents: none`, receives the
OIDC permission, and never executes repository code. The confirmation job also has no PR-write or
OIDC permission. The prototype is still not a production security boundary, because its measure
job must upload the transfer artifact after running customer code under the same OS identity; a
hostile surviving process could interfere with that upload/runtime channel. Publication therefore
requires a trusted transfer agent or hosted measurement boundary that customer code cannot access,
not another file-permission or environment-variable convention inside the same job.

The current `attest-results/v2` contract uses a closed Layer 0 reason set. Recognized legacy
Layer 0 acquisition reasons are normalized into that set;
when historical v1 data contains no Layer 0 evidence, the UI and API expose it
as historical/unavailable rather than inferring a pass or reconstructing lines
that were never uploaded.

When `abloh.yml` is present at the merge base and unchanged at the exact PR head, the workflow
hashes the trusted merge-base bytes and sends the repository-relative path, `sha256:` digest, and
source commit SHA. An introduced, removed, changed, symlinked, or non-regular policy is refused.
With no policy file it records `built-in-defaults`, a null path, and the digest of the canonical
built-in policy bytes. Submitted
thresholds are never authoritative by themselves: the control plane must fetch
the policy through its read-only App installation at that SHA and compare the
bytes/digest before accepting or enforcing the run.

The authenticated handoff returns exactly one opaque `runId`, exposed as the
reusable workflow's `run-id` output. The control plane binds that ID to the
OIDC repository/workflow claims. The production deployment must then notify
the GitHub App service through an authenticated internal completion channel;
that ingestion/notification endpoint is intentionally not faked in this
repository yet. The workflow does **not**
request `contents: write` and does not create a `repository_dispatch`; the
signed `repository_dispatch` adapter remains a compatibility trigger in the
current GitHub App runtime, not the default CI trust path.
