# Supplemental pinned PR verification

This workflow provides a bounded, read-only source scan for same-repository pull
requests into the owned fork's `dev` branch. It does not replace
`security-semgrep.yml`, its error-severity policy, Code Scanning ingestion, or the
team-member review required by `SECURITY.md`. It has no dispatch, push, release,
deployment, or privileged pull-request trigger.

The scanner is Semgrep **1.186.0** with metrics and version checks disabled. Rules
come from the public `semgrep/semgrep-rules` commit
`a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`. The manifest identifies 196 selected
JavaScript, TypeScript and GitHub Actions security rules and their namespaced IDs.
PyYAML **6.0.3** reconstructs the reviewed configuration byte for byte; its SHA-256
must be `da388503c6694eb209146d3ac991a6ae967ed00d99e4d5b3d44670f3cafb9b2a`.
Only public GitHub rule data is fetched; no code from that checkout is executed.
Semgrep uses the reconstructed local file, with no registry configuration.

The [Semgrep Rules License](https://semgrep.dev/legal/rules-license/) prohibits
redistribution. Rule content therefore remains in temporary runner storage,
alongside the upstream license notice and a notice describing selection and ID
changes. This repository contains the selector/provenance only, not the rules.

## Evidence and privacy

Raw SARIF, scanner stdout/stderr and detailed gate output remain on the ephemeral
runner, including failure paths. They are not printed or uploaded. The sole
artifact is `execution.json`: source SHA, scanner/core/distribution fingerprints,
rule/config identity, timestamps, exit statuses, execution success, severity
counts, report hash, numeric diagnostic totals/severity counts and coverage/skip
statistics when available. Notification IDs, messages and locations are excluded. Missing
statistics are `null`; oversize skips are not a claim to enumerate every skip.
This keeps untriaged vulnerability details out of public artifacts and logs.

The shared `semgrep_sarif.py` gate runs unchanged. Error findings still fail,
warnings retain the existing policy, and scanner failures preserve their exit
status. Missing, empty, malformed or structurally invalid reports fail closed.
Successful tool execution does not mean that findings are fixed or false positives.

## Trigger interaction at PR head 7ea9a2c

Updating `fix/fork-dev-semgrep-20261119` generates a feature-branch push and a
`pull_request/synchronize` event against `dev`. All eight existing workflows were
inspected before adding this workflow:

| Existing workflow | Event/filter consequence for this PR update |
| --- | --- |
| `security-semgrep.yml` | Pushes to `main`/`dev` and explicit dispatch only; the automatic-registry route is not triggered. |
| `build-packages.yml` | PR event matches, but all jobs require `dream-num/univer`; skipped in this fork. |
| `ci-quality-checks.yml` | PR event matches, but all jobs require `dream-num/univer`; skipped in this fork. |
| `collect-pr-metadata.yml` | PR event matches, but its job requires `dream-num/univer`; skipped in this fork. |
| `validate-pr-title.yml` | PR event matches, but its job requires `dream-num/univer`; skipped in this fork. |
| `dispatch-sync-univer-pro.yml` | Only `dev` pushes and the upstream repository; not triggered. |
| `sync-gitee-mirror.yml` | Only `main`/`dev` pushes and the upstream repository; not triggered. |
| `release-npm.yml` | Release-tag pushes and the upstream repository; not triggered. |

There is no existing `workflow_run`, `workflow_call` or `pull_request_target`
route. The regression suite verifies the relevant separation. No Actions setting
is changed; whether GitHub admits and executes the new workflow must be observed
after publication. A future merge to `dev` would independently match the original
automatic-registry workflow and requires a separate authorization assessment.

Action revisions were verified against their official repositories and pinned:
[checkout v7](https://github.com/actions/checkout/tree/3d3c42e5aac5ba805825da76410c181273ba90b1),
[setup-python v6](https://github.com/actions/setup-python/tree/ece7cb06caefa5fff74198d8649806c4678c61a1),
and [upload-artifact v7](https://github.com/actions/upload-artifact/tree/cf430e030ddbb5b0abf93d22962f4752f3646cd9).

Run the offline regressions after installing the pinned scanner and serializer:

```sh
python .github/scripts/test_semgrep_workflow.py
python .github/scripts/test_semgrep_pinned_pr.py
```

These controlled wrapper tests do not constitute a real hosted scan or SARIF
ingestion. The raw local rule reconstruction and any actual scanner execution
must be described separately from these tests.

## Fixed-baseline coverage recovery — 20 November 2026 AEDT

`baseline-coverage-recovery.yml` is a separate application-test workflow prepared
against PR head `4fe4c9911344e842b0f3c6e9e9a53515973818e7`. It is admitted only by
its exact filename and reviewed SHA-256 in `test_semgrep_pinned_pr.py`; changing
any byte or copying it under another filename requires another scope review.
The original workflow restrictions and automatic-registry gate remain intact.

The workflow runs only for same-repository updates to PR #1 in
`jaimalkiewicz1999-art/univer`, targeting `dev`, when one of its three control files
changes. It verifies the event's base SHA and checks out exactly
`618f9df2cb09e0dbe669b0dd0de5a9fbd5e6bb7f`, tree
`80581fa75b68b0d1e0398880a4516e1b3f957ff2`. This establishes missing **baseline**
evidence; it does not test the PR's application source. The event head and workflow
identity are recorded separately in the receipt.

Two isolated `ubuntu-24.04` matrix jobs run the complete engine-render and sheets-ui
coverage scripts, with no test-file or test-name filter. Their scripts, source,
lockfile and coverage configurations remain unchanged. Expected inventories are:

| Project | Test files | Passing assertions | Coverage sources |
| --- | ---: | ---: | ---: |
| engine-render | 107 | 2,359 | 226 |
| sheets-ui | 134 | 795 | 269 |

Both projects have zero declared skips in the retained source-identical candidate
reports. Each new report must independently prove those counts, success, zero
failures and zero skips. Every expected test path must occur exactly once; full
coverage source paths are checked against the fixed inventory. Tracked source,
project source hashes and shared configuration hashes are checked before and
after execution.

Each job has a 25-minute limit, an 18-minute test-command deadline, one worker and
no file parallelism. A fresh measurement immediately before testing must show at
least 4 GiB available after any applicable cgroup memory limit. The coordinator
uses 1,536 MiB old space; `--execArgv=--max-old-space-size=1024` sets the forked
worker's 1,024 MiB limit. Both retain a 16 MiB semi-space setting, and actual V8
heap limits are recorded. These are separate hosted runners. The existing 1 GiB
guard for the shared local executor is unchanged.

Checkout, pnpm setup and artifact upload reuse the existing exact action pins.
The job verifies Node 24.3.0, pnpm 12.5.1, Vitest 5.0.0 and the Istanbul coverage
provider 5.0.0. Dependencies use the frozen lockfile with no dependency cache.
The workflow requests only `contents: read`, does not persist checkout
credentials, and supplies no application secrets. It has no scanner, SARIF,
registry scan, release, deployment or publishing step.

Each artifact contains only `provenance.json`, `source-inventory.json`, the raw
`test-results.json` and `coverage-final.json`, derived `coverage-summary.json`, and
`test-stdout.log`. It contains no dependency cache, repository archive or raw
scanner output. Report bytes and SHA-256 hashes are retained before import.
Failed or missing reports cannot produce a successful acceptance receipt.

The later local import preserves the original artifact and raw JSON, changing
only verified absolute checkout-root prefixes in new normalized copies. It must
reject paths outside that root, duplicate paths, missing expected files and
statement/function/branch map changes. Each full hosted project replaces its
partial effective input; overlapping historical reports are not merged twice.
The final 60-project coverage comparison, all other required tests, real browser
and Excel clipboard checks, original scanner/ingestion acceptance and the
`SECURITY.md` team-member review remain separate gates.
