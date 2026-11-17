# CI on Every Commit — Goal Alignment

> Purpose: agree on *what* we want before changing `.github/workflows/`. Resolve every item in §5 before executing the implementation plan
> (`docs/superpowers/plans/2026-11-17-ci-every-commit.md`).

## 1. Current State (observed 2026-11-17)

| Item | Finding | Evidence |
|---|---|---|
| CI workflow | `.github/workflows/ci.yml` exists with 4 jobs: `build-fuzzer` (CMake build of `Fuzzer` + `proto-fuzzer`, `-help=1` smoke), `docker-build-fuzzer` (Docker `fuzzer` target), `format` (clang-format Google style on `src/`, `include/`), `unit-tests` (Docker `test` target → `ctest`) | file contents |
| CI triggers | `push` **only to `main`**, `pull_request` **only targeting `main`**. Commits on any other branch do **not** run CI. | `ci.yml` lines 3–9 |
| CD workflows | `deploy.yml` (Cloud Run job) and `gcp.yml` (push image to Artifact Registry) are **disabled** — `workflow_dispatch` only, push/cron triggers commented out ("public copy"). | file contents |
| Is it actually running? | **No. Zero workflow runs have ever been recorded** on `Siputroj/TPM-Fuzzer-AI`, even though `main` received pushes (latest `2eac8d5`, 2026-11-10). Actions is enabled (`allowed_actions: all`) and all 3 workflows are registered as `active`. | `gh run list` → "no runs found"; `gh api .../actions/runs` → `total_count: 0`; `check-runs` on `2eac8d5` → 0 |
| Test suite | One Catch2 binary `FUZZER_TESTS` (`tests/parser/byte_parser_test.cc`, `tests/harness/tpm_wrapper_test.cc`, `tests/harness/session_auth_test.cc`), only built with `-DRUN_UNIT_TESTS=ON`. | `tests/CMakeLists.txt`, `CMakeLists.txt:209` |
| Working tree | Uncommitted HMAC/NVRAM work (10 modified files, tracked in `docs/plans/HANDOFF.md`). CI results on that work are unknown. | `git status` |

**Terminology note:** what you described (every commit → run all tests) is **CI** (Continuous Integration). **CD** (Continuous Delivery/Deployment) is the disabled GCP image push / Cloud Run part.

## 2. Goal (revised 2026-11-17)

Every push to `main` and every PR into `main` automatically runs the repository **unit tests** (`tests/` → `FUZZER_TESTS` via `ctest`), the result is visible on the commit / PR, and `main` requires it to pass. CI does **not** run the fuzzer.

## 3. Success Criteria (definition of done)

1. Pushing to `main` and opening/updating a PR into `main` each create a `CI` run.
2. The run builds and executes `FUZZER_TESTS` (`ctest`) and reports per-test results.
3. A failing unit test makes the run fail (proven once on a throwaway PR).
4. Superseded runs on the same PR are cancelled automatically.
5. Branch protection on `main` requires `Run unit tests`.
6. Green CI on `main` HEAD after the change lands.

## 4. Non-Goals

- Re-enabling CD (GCP image push / Cloud Run) — this is a public copy without GCP credentials.
- Long fuzzing campaigns or coverage reports in CI (only the 60 s smoke run).
- Fixing pre-existing test/format failures beyond what is needed for green CI (those get logged and handled separately).

## 5. Decisions

| # | Question | Decision |
|---|---|---|
| D1 | Trigger scope | `main` pushes + PRs into `main` (+ manual `workflow_dispatch`) |
| D2 | Run on docs-only commits? | Yes, no path filters |
| D3 | Fuzzer smoke run? | Yes — 60 s of `Fuzzer` on `seeds/bytearray` in `build-fuzzer`; fails on crash |
| D4 | Branch protection on `main`? | Yes, require `Run unit tests` |
| D5 | Order vs HMAC/NVRAM work | CI change first, on its own branch |
| Q1 | Other CI jobs | Keep `format` + `build-fuzzer`; drop `docker-build-fuzzer` |

## 6. Risks

- **Root cause of zero runs is unknown.** Possible causes: account-level Actions restriction/billing hold, runs deleted, or history pushed in a way that did not emit push events. Task 1 of the plan diagnoses this before any YAML changes; if runs cannot be created at all, that is an account setting only you can change.
- **Build time:** unit tests compile the whole TPM reference implementation inside Docker with no caching; expect 10+ min per run until Docker layer caching is added (included in plan).
- **First real run may be red** (format drift, compile errors in the newer `tests/` changes) — expected; plan includes a triage task.
