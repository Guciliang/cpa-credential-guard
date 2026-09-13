# CPA Credential Guard

CPA Credential Guard is a narrow Codex-only CLIProxyAPI dynamic plugin. It observes completed usage records, classifies explicit quota exhaustion, and uses CPA's Host API to mutate only the native `disabled` or `proxy_url` field. It does **not** replace CPA scheduling, routing, request execution, interception, or retry behavior.

## Build

The plugin is pinned to the published CPA v7 SDK contract (`v7.2.157`). The module uses the normal Go module download path so builds do not depend on a research checkout; offline deployments should provision that approved module through their normal Go proxy or module cache.

```sh
make fmt
go test ./...
go vet ./...
make build
```

`make build` produces `bin/cpa-credential-guard.so` on Linux (`.dylib` on macOS and `.dll` on Windows) using `go build -buildmode=c-shared`.

## Distribution and one-click installation

Local compilation is intended for development and isolated CPA testing. For normal installation, the repository uses GitHub Actions to build platform-matched dynamic libraries and publish the release assets that CPA's plugin store expects.

The release workflow is triggered by a tag such as `v0.1.0` and publishes:

```text
cpa-credential-guard_0.1.0_linux_amd64.zip
cpa-credential-guard_0.1.0_linux_arm64.zip
cpa-credential-guard_0.1.0_darwin_amd64.zip
cpa-credential-guard_0.1.0_darwin_arm64.zip
cpa-credential-guard_0.1.0_windows_amd64.zip
checksums.txt
```

Each zip contains exactly one library at its root (`cpa-credential-guard.so`, `.dylib`, or `.dll`). CPA verifies the SHA-256 checksum and extracts the artifact for the running OS/CPU architecture; it does not compile the Go source on the CPA machine.

The repository address for this plugin is:

```text
https://github.com/Guciliang/cpa-credential-guard
```

When the CPA version supports adding a plugin repository directly, enter that HTTPS repository URL—not the SSH URL, a source-file URL, or a zip URL. The repository must have at least one valid `v<major>.<minor>.<patch>` GitHub Release produced by the workflow. If the CPA UI only shows plugins from a registry, the same repository must additionally be added to the CPA plugin-store registry; the official store keeps registry metadata while release binaries remain in this repository.

To publish a release after the workflow is committed:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The tag/push commands are release operations and must be run by the repository owner. Docker deployments must use an artifact built for the container's OS and architecture, and the configured `state_dir` must remain under the persisted CPA plugins volume.

## Configuration

The plugin is inert unless both CPA enables the plugin and its own `enabled` setting is true. Conservative defaults include explicit quota evidence for 429 classification, generic rate-limit classification disabled, Codex-only recovery, no model/prompt probe, a ten-minute minimum scan interval, and bounded backoff.

```yaml
enabled: false
state_dir: plugins/cpa-credential-guard-data
recovery_enabled: true
scan_interval: 10m
initial_backoff: 15m
max_backoff: 24h
probe_enabled: true
probe_provider: codex
probe_model: ""
probe_timeout: 10s
quota_detection_enabled: true
detect_http_429: true
classify_generic_rate_limit: false
proxy_management_enabled: true
```

`state_dir` is explicit and durable. The plugin never falls back to a temporary directory, the current working directory, or `AuthDir`. When CPA runs in Docker with a custom `plugins.dir`, configure `state_dir` as a subdirectory below the persisted plugins volume, for example `/data/plugins/cpa-credential-guard-data`, and mount that directory across restarts. Empty, unsafe, inaccessible, or invalid state configuration leaves automatic writes disabled.

## Safety boundaries

* Every credential write is `host.auth.get` → one top-level field mutation → `host.auth.save`; unknown fields are preserved semantically.
* Recovery requires a persisted plugin-owned record and an unchanged content/runtime guard. Manual or unverifiable changes move to manual review without overwrite.
* Recovery uses exactly one bounded credential-scoped `GET https://chatgpt.com/backend-api/wham/usage` request. The transient access token is never persisted, logged, displayed, or passed to proxy tests.
* Proxy checks use a separate bounded HTTP/SOCKS transport and a fixed non-Codex HTTPS target. They never accept an AuthIndex or credential JSON and never fall back to a direct connection after proxy setup fails.
* The static sidebar resource contains no dynamic data. Authenticated management routes return only redacted endpoints, fingerprints, safe status, and independent per-item results.
* The plugin declares only `usage_plugin` and `management_api`; it does not register a scheduler/router/executor/interceptor and does not implement a custom 502 retry.

* The authenticated management routes are under `/v0/management/plugins/cpa-credential-guard/`: `GET /status`, `POST /proxy/preview`, `POST /proxy/apply`, `POST /proxy/test`, and `POST /recovery/scan`. The browser resource is `/v0/resource/plugins/cpa-credential-guard/index.html` and contains no server-rendered credential data.
* Proxy preview plans expire after five minutes, are revalidated against a fresh Host API snapshot, and return independent per-item results for heterogeneous batches. Raw proposed proxy URLs exist only in the short-lived in-memory plan and are not returned or written to state.

See `NOTICE.md` for SDK/direct dependency and behavioral-reference notices. No Sub2API LGPL source or codex-429-autoban scheduler behavior is copied.
