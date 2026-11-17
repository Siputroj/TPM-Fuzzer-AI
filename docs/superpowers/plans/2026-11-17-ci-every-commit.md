# CI Unit Tests on `main` + PRs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every push to `main` and every PR into `main` runs the repository unit tests (`tests/` → `FUZZER_TESTS` via `ctest`) on GitHub Actions, and `main` requires that check to pass.

**Architecture:** Surgical edits to the existing `.github/workflows/ci.yml` (no new workflow files). Triggers stay `main` + PRs; add `workflow_dispatch` and concurrency; cache the Docker `test` image build. Keep `format` + `build-fuzzer` (plus a 60 s fuzzer smoke run), drop `docker-build-fuzzer`.

**Tech Stack:** GitHub Actions, Docker Buildx, CMake/Ninja, Catch2 v3 / ctest.

**Spec:** `docs/superpowers/plans/2026-11-17-ci-every-commit-goal-alignment.md` (decisions D1–D5 as answered 2026-11-17).

## Global Constraints

- Work on branch `ci/unit-tests`, never directly on `main`. Land before the HMAC/NVRAM work (D5).
- Keep `permissions: contents: read`.
- Do not touch `deploy.yml` / `gcp.yml` (CD stays disabled).
- Pin actions to the major versions already used (`actions/checkout@v5`, `docker/build-push-action@v6`); add `docker/setup-buildx-action@v3`.
- Verification of every task = an observed GitHub Actions run (`gh run list --repo Siputroj/TPM-Fuzzer-AI`), not local reasoning.

## Review Focus

1. PR from `ci/unit-tests` into `main` → exactly one `pull_request` run with the `Run unit tests` check.
2. A failing Catch2 assertion must fail the job (container exit code propagates) — proven in Task 3.
3. A test binary that fails to *compile* must fail the job (Docker build step fails).
4. Docs-only commit to `main` still triggers CI (D2).
5. New push to the same PR cancels the older in-flight run.

---

### Task 1: Diagnose why no run has ever been created

**Files:** none (diagnostic only)

- [ ] **Step 1:** Do Task 2 Step 1–2 (adds `workflow_dispatch`), push `ci/unit-tests`, open a draft PR into `main`.
- [ ] **Step 2:** `gh run list --repo Siputroj/TPM-Fuzzer-AI --limit 5` — Expected: one `pull_request` run appears.
  - If no run → check https://github.com/Siputroj/TPM-Fuzzer-AI/settings/actions and account Actions/billing settings. **Mark BLOCKED and report to user** (account setting, not code).
- [ ] **Step 3:** Record per-job outcome in the HANDOFF ledger as the baseline.

### Task 2: Triggers, manual dispatch, concurrency

**Files:** Modify `.github/workflows/ci.yml:3-9`

- [ ] **Step 1:** Replace the `on:` block with:

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

concurrency:
  group: ci-${{ github.event_name }}-${{ github.ref }}
  cancel-in-progress: true
```

- [ ] **Step 2:** `git checkout -b ci/unit-tests && git commit -am "ci: add manual dispatch and concurrency" && git push -u origin ci/unit-tests`
- [ ] **Step 3:** Push a second commit while the first run is in progress; Expected: first run `cancelled`.

### Task 3: Cache the unit-test Docker build + prove red

**Files:** Modify `.github/workflows/ci.yml` job `unit-tests`; throwaway edit to `tests/parser/byte_parser_test.cc`

- [ ] **Step 1:** Add `- uses: docker/setup-buildx-action@v3` after checkout.
- [ ] **Step 2:** Replace `docker build --target test ...` with `docker/build-push-action@v6`: `target: test`, `load: true`, `push: false`, `tags: tpm-unit-tests`, `cache-from: type=gha,scope=test`, `cache-to: type=gha,mode=max,scope=test`. Keep `docker run --rm tpm-unit-tests`.
- [ ] **Step 3:** Push; Expected: `Run unit tests` runs `ctest` and lists all Catch2 test cases; second push shows `CACHED` layers.
- [ ] **Step 4:** On throwaway branch `ci/prove-red`, add `TEST_CASE("ci canary") { REQUIRE(1 == 2); }`, open a draft PR; Expected: `Run unit tests` **fails**. Close PR, delete branch, record run URL.

### Task 3b: Fuzzer smoke run

**Files:** Modify `.github/workflows/ci.yml` job `build-fuzzer`

- [ ] **Step 1:** After `Verify`, add `Fuzzer -max_total_time=60 -artifact_prefix=smoke-artifacts/ smoke-corpus seeds/bytearray` and an `upload-artifact@v4` step on failure.
- [ ] **Step 2:** Expected: step runs ~60 s and passes.

### Task 4: Triage first run to green

- [ ] **Step 1:** For each red job: `gh run view <id> --log-failed`.
- [ ] **Step 2:** Test failures on committed `main` code → superpowers:systematic-debugging; failures caused by the uncommitted HMAC work don't apply (not in this branch).
- [ ] **Step 3:** Expected: `Run unit tests` green on the PR.

### Task 5: Land and protect `main`

- [ ] **Step 1:** Mark PR ready; merge after user review; confirm a `push` run on `main` is green.
- [ ] **Step 2 (D4):** Enable branch protection on `main` requiring status check `Run unit tests` (plus any other jobs kept per open question Q1).
- [ ] **Step 3:** Point README CI badge at `https://github.com/Siputroj/TPM-Fuzzer-AI/actions/workflows/ci.yml/badge.svg` if not already.
