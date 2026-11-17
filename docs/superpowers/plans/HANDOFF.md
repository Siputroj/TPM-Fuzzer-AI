# Implementation Progress & Session Handoff — CI on `main` + PRs

> Separate from `docs/plans/HANDOFF.md` (HMAC/NVRAM plan, still in progress).
> Every `[x] DONE` entry MUST be backed by an observed commit SHA or GitHub Actions run URL.

## 1. Plan Metadata

- **Plan:** `docs/superpowers/plans/2026-11-17-ci-every-commit.md`
- **Spec:** `docs/superpowers/plans/2026-11-17-ci-every-commit-goal-alignment.md`
- **Branch:** `ci/unit-tests` (worktree `.worktrees/ci-unit-tests`), PR https://github.com/Siputroj/TPM-Fuzzer-AI/pull/1
- **Base Commit:** `2eac8d5`
- **Last Updated:** `2026-11-17 03:06`
- **Overall Status:** `AWAITING_USER_MERGE`

## 2. Progress Matrix

| Task # | Task Name | Status | Evidence |
|---|---|---|---|
| 1 | Diagnose zero-run history | `[x] DONE` | PR #1 created run 44069530242 → Actions works; zero history was simply no qualifying trigger events reaching this repo |
| 2 | Triggers, dispatch, concurrency | `[x] DONE` | `2533f58` |
| 3 | Cache unit-test build + prove red | `[x] DONE` | `2533f58`; canary PR #2 run 44070230117 failed on `ci canary - must fail` (closed, branch deleted) |
| 3b | Fuzzer smoke run | `[x] DONE` | run 44069530242: `Done 79942 runs in 61 second(s)` |
| 4 | Triage first run to green | `[x] DONE` | run 44069530242: all 4 jobs green, ctest 17/17 |
| 5 | Land + protect `main` | `[ ] TODO` | needs user to merge PR #1, then branch protection |

## 3. Rulings

- `Ruling:` Combined Tasks 2/3/3b/README badge into one commit `2533f58` — single small YAML file, one CI run verifies all — cost if wrong: coarser history.
- `Ruling:` Did tasks in worktree off `origin/main` — keeps uncommitted HMAC work out of the CI branch — none.
- `Ruling:` Updated README CI badge to `Siputroj/TPM-Fuzzer-AI` (pointed at old upstream org) — cost if wrong: badge shows this fork's status.
- `Final: fixed` concurrency cancelled push-to-main runs → `cancel-in-progress` only for `pull_request`.
- `Final: fixed` UBSan reports non-fatal in smoke run → `UBSAN_OPTIONS=halt_on_error=1` on smoke step (not provable red without a real overflow).
- `Final: fixed` (re-graded Minor→Important) `ctest` exits 0 with zero tests → `--no-tests=error`.

## 4. Deferred minors

- `minor (deferred)` smoke run lacks `-timeout=25 -rss_limit_mb=2048` / job `timeout-minutes`.
- `minor (deferred)` crash-artifact upload `if: failure()` also fires on build failure (harmless).
- `minor (deferred)` `build-fuzzer` doesn't apply `config/determinism.patch` (Docker does) — possible non-reproducible smoke failures.
- `minor (deferred)` format job: unquoted `$files`, no `.cpp/.cxx` (pre-existing).
- `minor (deferred)` Node 20 deprecation warning for `docker/build-push-action@v6`, `docker/setup-buildx-action@v3`; `ubuntu-latest` → Ubuntu 26 migration notice.

## 5. Exact Next Action

1. User reviews and merges PR #1.
2. Confirm green `push` run on `main`.
3. Enable branch protection on `main` requiring `Run unit tests`, `Build Fuzzer binary`, `Check code format (src)`, `Check code format (include)`.
4. Remove `.worktrees/ci-unit-tests`.
