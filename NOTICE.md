# Notices

CPA Credential Guard is an independently written plugin. CPA core and SDK source files are not modified.

## CPA SDK

* `github.com/router-for-me/CLIProxyAPI/v7`, compatible with the researched v7.2.157 checkout at `/workspace/.research/CLIProxyAPI`. The SDK's applicable license and copyright notice remain with the SDK distribution.

## Direct dependencies

* `gopkg.in/yaml.v3` (MIT) — YAML decoding. See the dependency's distribution for its copyright and full license text.
* `golang.org/x/net` (BSD-3-Clause) — SOCKS5 transport support. See the dependency's distribution for its copyright and full license text.

## Narrow MIT pattern adaptations

The following repositories were audited and their isolated behavioral patterns were reimplemented/narrowed, not imported as packages or copied complete plugins:

* `Mxucc/cpa-account-config-manager`, revision `734a6a3` — preview expiry/revalidation and independent batch result ideas.
* `JefferyZhang2019/cpa-plugin-codex-auto-reset`, revision `647d0cc` — bounded `wham/usage` request and response handling ideas.
* `JiMu-cn/cpa-bark-notifier`, revision `03069f7` — bounded transport and atomic replacement ideas.
* `xg1990/quota-pacer`, revision `8bdee9b` — defensive Codex quota-window/header parsing ideas only.
* `Cody292/quota-activation`, revision `ee5c6e1` — versioned state and safe projection ideas only.
* `dinhkarate/cpa-quota-api-extension`, revision `a1873f6` — safe quota status projection ideas only.
* `RayenAlex/quota-center`, revision `01f9d24` — bounded host response/projection ideas only.
* `lij768423-svg/grok2api-egress-enhancements`, revision `b0cb59b` — post-save verification and redacted endpoint projection ideas only.
* `simplez2/cpa-codex-agent-identity`, revision `77588ba` — bounded proxy test quality ideas only.

Each listed plugin was reported as MIT in the audit. No source file, scheduler, priority/weight, affinity, private ban pool, token refresh, reset-credit, or inference-probe subsystem was copied.

## Behavioral-only references (no source copied)

* CPA-Manager-Plus (`e19d8267a52ca146c43bdb86d185bb7baed7ff38`) — Codex `GET /backend-api/wham/usage` inventory shape and quota-window behavior.
* Sub2API (LGPL-3.0) — token-free bounded proxy connectivity behavior only. No Sub2API source is included.
* `codex-429-autoban` — explicitly excluded; its scheduler/ban behavior is not used.
