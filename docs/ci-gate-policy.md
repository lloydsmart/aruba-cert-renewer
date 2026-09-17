# Common pull request CI gate

Every pull request to `main` starts `Pull request CI` without a path filter.
The stable final check remains `Required CI gate`. Actions lint, Markdown lint,
Ruff, the complete Python 3.12/3.14 matrix, dependency-lock freshness, Gitleaks
full-history scanning, and dependency vulnerability scanning run on every PR.
The jobs use read-only repository permissions and no inherited secrets.

## Container relevance

Only additions or modifications to `README.md`, `CONTRIBUTING.md`,
`CHANGELOG.md`, or Markdown files under `docs/` can skip container validation.
All other inputs require it, including workflow, policy, baseline, dependency,
source, test, configuration, and unknown paths. Empty diffs also run it.
Deletions and type changes require validation, even within documentation.
Renames are deliberately reported as delete/add pairs, covering both names.
The detector compares the PR merge base to its head using NUL-delimited Git
output, without external diff/text conversion. Invalid inputs fail closed.

The common caller forces the complete deployment workflow when relevant.
UniFi's older standalone push filter cannot skip validation selected by this
caller. UniFi's standalone documentation pushes keep their existing successful
skip behavior; the extra all-jobs-success receipt runs only for the forced PR
call. Aruba includes both Hadolint/Compose checks and container smoke/scans.
Existing standalone push, schedule, and manual triggers remain available.
Aruba's independent PR workflows are retained during the transition so existing
check contexts remain available; some checks run twice until protection settings
are verified and a later cleanup removes those duplicate PR triggers.

## Result contract

| Condition | Required gate outcome |
| --- | --- |
| Every mandatory job and internal check succeeds | Pass |
| Container relevance is `false`, deployment is exactly skipped | Pass if all mandatory checks passed |
| Failure, cancellation, or unexpected skip in mandatory work | Fail |
| Missing, malformed, extra, or unrecognized job/relevance results | Fail |
| Overall workflow succeeds but an internal check did not | Fail |

Reusable workflows expose a `passed` output only when every required internal
job reports success. The aggregate gate checks that output as well as the
workflow result. Aruba's nested deployment workflows propagate both levels.
Python matrix failure remains a failure; `fail-fast: false` permits both
runtimes to finish and does not permit a failed result. No `continue-on-error`
is used. The gate uses `always()` and a five-minute timeout; a cancelled or
unavailable gate cannot be treated as a passing gate. New commits cancel older
PR runs, with the newest commit requiring its own successful check.

The identical `scripts/ci_policy.py`, `tests/test_ci_policy.py`, and orchestrator
in both projects define the shared contract. Tests exercise rejected results,
internal-job output wiring, malformed inputs, renamed/deleted paths, and the
no-change case. Product-specific build commands and dependency locks remain
separate. All runner jobs in this PR graph have explicit timeouts.

## Enforcement and trust boundary

Workflow code establishes a check; repository protection must separately
require that check. On 17 September 2026, UniFi's inspected `Protect main`
ruleset requires `Required CI gate` from GitHub Actions, without strict
freshness. Aruba's inspected ruleset has no required-status-check rule. Classic
branch protection remains unverified. This change does not alter settings or
claim Aruba merges are already blocked by this gate.

After observing the new check on ordinary PRs, separately review requiring it
in both repositories, strict freshness, and resolved review threads. Preserve
signed commits, CodeQL, and the sole-maintainer manual merge model. Do not remove
an existing required context before its replacement is registered and passing.

PR code can change its own gate and tests. These controls detect accidental
omissions and enforce the declared graph; they do not establish an independent
trust boundary against a malicious maintainer changing that graph. Human review
of workflow/security changes remains necessary. CodeQL stays independently
required by the existing repository rules; release qualification and publisher
isolation are separate audit work.

GitHub documents [job dependency and `always()` semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idneeds)
and [reusable workflow outputs](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#using-outputs-from-a-reusable-workflow).
