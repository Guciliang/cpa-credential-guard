# Journal - Guciliang (Part 1)

> AI development session journal
> Started: 2026-09-11

---

## 2026-09-13 — Targeted similar-plugin audit and replanning

- Completed the requested read-only review of functionally similar CPA plugins in `/workspace/.research/plugins`; this was targeted rather than an unsupported claim of reviewing all 61 registry entries.
- Recorded source/revision/license findings in `.trellis/tasks/09-13-cpa-credential-guard/research/default-plugin-audit.md` and updated the license boundary.
- Selected narrow MIT patterns for possible adaptation: preview-plan revalidation, bounded `wham/usage` and Codex quota parsing, atomic persistence, and proxy transport/redaction. `codex-429-autoban` remains explicitly excluded; no Sub2API LGPL source is copied.
- Replanned pending recovery as a persisted state machine with phase-specific runtime/content guards; unverifiable interrupted enables move to `manual_review` rather than automatic probing or overwrite.
- Task remains `planning`; no product source, `task.py start`, commit, or push was performed.

## 2026-09-13 — Credential Guard implementation and final verification

- User approved implementation; task was activated and the CPA Credential Guard product source, static sidebar UI, tests, build files, and notices were added.
- The module uses the standard public `github.com/router-for-me/CLIProxyAPI/v7 v7.2.157` dependency with `go.sum`; no local absolute `replace` directive remains.
- Final quality review passed `gofmt`, `go test ./...`, `go vet ./...`, `go test -race ./...`, `go mod verify`, and `go build -buildmode=c-shared`. No live CPA host/management or external proxy E2E environment was available.
- Updated backend/frontend code-specs with Host API field-preservation, fail-closed state/recovery, safe logging, management/UI projections, proxy-test, and cross-layer security contracts.
- No commit or push has been performed; commit still requires separate explicit user approval.

## 2026-09-13 — Local CPA dynamic-library integration verification

- Built a c-shared plugin against the public CPA SDK and loaded it into an isolated local CPA v7.2.157-compatible process using a separate `plugins.dir`, `state_dir`, `auth-dir`, and `fill-first` routing configuration.
- Confirmed CPA loaded and registered `cpa-credential-guard` with only usage and management capabilities. The sidebar resource initially returned `404` through the dynamic callback because the static resource handler was only represented in the in-process registration; the service now normalizes `/v0/resource/plugins/cpa-credential-guard/index.html` and serves the static shell through the dynamic management callback. Added a regression test and reverified the resource returned HTTP 200.
- Real CPA checks passed: management routes required the Management Key (`401` without it, `200` with it); the static sidebar returned `200`; status returned redacted credential/proxy projections and proxy groups without fake credential tokens.
- Added two synthetic Codex auth fixtures containing only test values. Real CPA Host API-backed preview/apply tests verified single proxy replacement, clear, heterogeneous batch updates, continuation after a missing-credential item, and preservation of every unrelated JSON field. A stale preview was invalidated safely after an external file change (`409`, no overwrite).
- Ran a local CONNECT proxy that forwarded the fixed non-Codex HTTPS check target. The real CPA management route returned one successful proxy test (`HTTP 204`) and one independent unreachable-proxy failure; a proxy URL with userinfo returned only a redacted endpoint/fingerprint.
- The local CPA process and test proxy were stopped after verification. Codex quota callback/recovery against a real credential and production-like CPA traffic remain untested; unit/fake-Host tests cover those paths.
- Product source remains uncommitted and unpushed.

## 2026-09-13 — GitHub Release distribution path

- Confirmed from the CPA plugin-store contract that local `make build` is for development only; CPA installs platform-specific compiled dynamic-library artifacts rather than Go source.
- Added GitHub Release distribution requirements and workflow for `https://github.com/Guciliang/cpa-credential-guard`: `v<major>.<minor>.<patch>` tags, Linux amd64/arm64, Darwin amd64/arm64, and Windows amd64 artifacts, root-level library zips, and release-level `checksums.txt`.
- Corrected the plugin registration metadata, which previously pointed at the CLIProxyAPI core repository; it now points to the plugin repository and supports release-version injection through `-ldflags`.
- Documented the distinction between direct repository installation (when supported by the CPA UI) and appearing in the official plugin-store registry. No commit, tag, or push was performed.

## 2026-09-13 — Saved proxy profiles, configurable sidebar, and v0.1.7 release

- Added the persistent `state_dir/proxy-profiles.json` catalog with restrictive permissions, atomic replacement, corrupt-catalog quarantine, duplicate-remark validation, and remark-only/redacted management projections.
- Reworked proxy assignment and connectivity testing to select saved profile remarks, while preserving single-credential, shared-batch, heterogeneous-batch, preview, stale-plan, and partial-failure behavior. Removed the technical fingerprint from user-facing/API projections.
- Converted configurable boolean settings in the sidebar into real switches saved through CPA's authenticated plugin configuration endpoint, and added spacing/responsive layout improvements. Kept the two embedded HTML resources byte-identical.
- Re-ran unit, race, vet, module, format, diff, JavaScript, embedded-resource, and c-shared build checks successfully.
- Committed implementation as `0396589` and release metadata as `5e5aaaa`; pushed `main`, tagged and pushed `v0.1.7`. GitHub Actions run `34876132815` completed successfully, and all five release archives plus `checksums.txt` passed public checksum and root-library layout verification.
- Real production Codex quota recovery remains outside this verification because no live credential was used; local fake-Host and management/proxy tests cover the changed paths.

## 2026-09-15 — Manual quota query decision for sidebar pagination task

- User clarified that newly installed credentials should initially show quota as unknown rather than triggering automatic upstream checks.
- Added a global `查询全部额度` action in the Codex credential panel and an individual `查询额度` action on each row, so a new credential can be checked without querying all credentials again.
- The planned management route is authenticated and manual-only: it calls the existing exact-credential `GET /backend-api/wham/usage`, persists only safe quota/reset metadata bound to a non-secret credential identity/content hash, and continues after per-credential failures.
- `/status`, plugin installation, refresh, and the ordinary recovery ticker must not perform broad quota polling. Manual quota query, recovery probing, normal CPA `UsageRecord`, and active real wake-up remain separate evidence paths.
- Updated `.trellis/tasks/09-15-sidebar-proxy-pagination/{prd.md,design.md,implement.md,research.md,implement.jsonl,check.jsonl}`. Product source remains untouched and implementation still awaits the separate final planning approval and task activation.

## 2026-09-15 — Finalized active wake-up semantics

- User confirmed the final active-wake defaults: model `gpt-5.6-luna`, reasoning effort `low`, and fixed prompt `Hello`; all other reviewed recommendations are accepted.
- The planning contract now uses one shared bounded scan coordinator controlled by `scan_interval`. `recovery_enabled` controls only automatic recovery; `probe_enabled` gates all `wham/usage` reads and manual quota queries, while initial wake does not require it and reset wake requires an existing valid reset window.
- Successful normal Codex `UsageRecord` values are separate from active-wake evidence. Failed or ambiguous normal requests enter safe unknown/manual review rather than immediately causing another real request. Reset wake generations bind credential identity and the latest valid blocking reset time, and successful generations are idempotent across restart.
- Active wake protocol success requires a complete parseable Responses JSON or valid stream terminal event; HTTP 2xx alone is insufficient. Network/timeout retries are capped at three with bounded backoff, authentication/quota failures stop the current attempt family, protocol failures require review, and no wake failure automatically disables a CPA credential.
- Updated the sidebar-proxy-pagination PRD, technical design, implementation plan, and research notes. Product source remains untouched; task activation and implementation still require the user's separate explicit approval.

## 2026-09-15 — Implemented sidebar proxy pagination, manual quota queries, and active wake-up

- Implemented fixed token-free proxy quality checks for base connectivity, OpenAI, Anthropic, Gemini, and Grok with bounded bodies, safe per-target classifications, latency, summary counts, and redacted projections. The legacy single-target checker remains for compatibility.
- Added explicit authenticated quota querying with `{}` for all Codex credentials and `{"auth_index":"..."}` for one credential. `/status` and normal scans do not query quotas; results are identity-bound sanitized observations with per-item continuation and `probe_enabled` gating.
- Added independent default-off initial/reset active wake-up records and a bounded fixed Codex request path using model `gpt-5.6-luna`, effort `low`, and prompt `Hello`. Wake records, normal CPA usage, health checks, and manual quota reads remain separate and secret-free.
- Rebuilt the Chinese dark sidebar around the unified `代理板块`, credential pagination (default 10; 5/10/15/20/30/40/50 choices), current-page selection, in-panel proxy results, batch proxy controls, safe quota states, and per-row/global manual quota actions. Root and embedded HTML remain byte-identical.
- Updated README and backend/frontend code-specs with the new API, state, projection, and security contracts.
- Validation passed: `gofmt`, `go test -count=1 ./...`, `go test -count=1 -race ./...`, `go vet ./...`, `go mod verify`, c-shared build, JavaScript syntax check, static security assertions, `git diff --check`, and HTML synchronization. Product changes remain uncommitted and unpublished pending separate commit authorization.

## 2026-09-15 — Final audit hardening and verification

- Tightened non-stream wake success validation so `status: completed` requires a non-empty, structurally valid Responses output; null, empty, missing, or malformed output remains `wake_protocol_failed`.
- Mapped wake authentication, quota, and protocol failures to distinct actionable sidebar text; serialized global/row quota queries and added a session generation so stale requests cannot overwrite a new session or leave loading markers stuck.
- Made proxy warning/challenge summary counts distinct from failures, added invalid-response handling, and kept the server-owned five-target catalog unchanged.
- Removed secondary scan-interval normalization from both wakeup and legacy recovery managers; the validated controller configuration is authoritative, with invalid direct-manager intervals inert rather than silently rewritten.
- Optional ownership metadata is sanitized and discarded/reduced independently of required ownership identity, so malformed quota/probe/wake entries cannot quarantine otherwise usable state. Added regression coverage for current manual quota precedence and stale credential identity.
- Final verification repeated after hardening: full unit tests, race tests, vet, module verification, c-shared build, extracted-sidebar JavaScript syntax check, synchronized HTML comparison, static security assertions, and `git diff --check` all passed. No commit or push was performed.
- After explicit user authorization, committed the 22-file implementation as `df8176e feat: refine sidebar proxy and credential wake management`. The two generated validation artifacts were moved into the ignored `.trash/` directory; no push was performed.



## Session 1: Sidebar proxy pagination and credential wake-up
<!-- trellis-session: v=2 fp=6f19c35ec1d977d9 -->

**Date**: 2026-09-20
**Task**: Sidebar proxy pagination and credential wake-up
**Branch**: `main`

### Summary

Completed the unified Chinese dark sidebar proxy board with fixed token-free multi-target checks, paginated Codex credential proxy assignment, explicit quota queries, safe quota/wakeup projections, independent default-off active Codex wakeups, persistence hardening, and regression coverage. Final Go tests, race, vet, module verification, c-shared build, JavaScript syntax, security assertions, synchronized HTML, and diff checks passed. Committed as df8176e; no push.

### Git Commits

| Hash | Message |
|------|---------|
| `df8176e` | feat: refine sidebar proxy and credential wake management |

### Status

[OK] **Completed**


## Session 2: Credential Guard sidebar fix and v0.1.9 release
<!-- trellis-session: v=2 fp=7bf9f6d8b940f75c -->

**Date**: 2026-09-20
**Task**: Credential Guard sidebar fix and v0.1.9 release
**Branch**: `main`

### Summary

Implemented and verified the Credential Guard sidebar layout, proxy selection/persistence flow, quota-result presentation, safe operation feedback, and synchronized embedded HTML. Ran Go tests, race tests, vet, module verification, UI/browser checks, and real Chromium screenshot validation. Committed as bfbd5ec, pushed main, created and pushed v0.1.9, and verified the successful GitHub Actions release with five platform archives and checksums.

### Git Commits

| Hash | Message |
|------|---------|
| `bfbd5ec` | fix: refine credential guard sidebar proxy and quota feedback |

### Status

[OK] **Completed**
