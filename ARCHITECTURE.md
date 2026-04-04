# OpenCircuit Architecture

## Runtime Overview

- Application code lives under `app/` and is grouped by concern.
- `app/runtime/server.py` is the app-factory composition layer for HTTP/WS runtime.
- `app/runtime/settings.py` centralizes runtime env parsing.
- `app/cli/flow.py` contains interactive console display and identify/naming workflow.
- `app/network/scanner.py` runs periodic background scans and keeps in-memory history.
- Scan pipeline is split by concern under `app/network/scan/`:
  - `app/network/scan/ping.py` for host generation and ping sweep
  - `app/network/scan/dns.py` for reverse DNS
  - `app/network/scan/arp.py` for MAC/vendor discovery
  - `app/network/scan/mdns.py` for mDNS query/parse/discovery
  - `app/network/scan/probe.py` for TCP/HTTP/SSDP/UPnP probing and service identification
  - `app/network/scan/assembly.py` for end-to-end scan orchestration and label assembly
- `app/http/server_auth.py` contains API/WS auth and origin policy.
- `app/http/server_ws.py` contains websocket lifecycle and broadcast manager.
- `app/http/server_routes.py` contains HTTP route handlers.
- Root-level modules (e.g. `server.py`, `scanner.py`, `identity.py`) are compatibility aliases for legacy imports.
- Root-level `main.py` remains the single launch entrypoint and forwards to `app/runtime/main.py`.
- `web/ui` contains the Svelte dashboard, built into `web/static-svelte`.
- Frontend live sync lifecycle is split into:
  - `web/ui/src/lib/live-feed.ts` for WS/poll/reconnect/heartbeat transport
  - `web/ui/src/lib/dashboard-state.ts` for payload-to-state transformations

## Backend Domain Contracts

- `app/domain/models.py` defines typed scan models:
  - `LabelInfo`
  - `DeviceFingerprint`
  - `ScannedDevice`
- `ScannedDevice.to_record()` is the canonical conversion into legacy dictionary payloads.
- `app/domain/identity.py` owns strict label resolution and alias assignment.
- `app/runtime/settings.py` centralizes environment parsing and runtime settings.
- `app/network/scan/assembly.py::run_single_scan(...)` is the canonical scan orchestration API.

## Persistence

- `app/storage/device_history.py` persists rolling scan state (`devices.json`).
- `app/storage/known_devices.py` persists user-assigned names (`known_devices.json`).
- `app/storage/secure_storage.py` provides atomic JSON writes and symlink protection.

## Quality Gates

- Backend tests: `python3 -m pytest -q`
- Backend tests location: `tests/`
- Frontend checks: `cd web/ui && npm run check`
- Frontend build: `cd web/ui && npm run build`

CI workflows:

- `.github/workflows/ci.yml` for tests/checks/build.
- `.github/workflows/security-audit.yml` for dependency vulnerability audits.

## Next Refactor Targets

- Introduce app-level integration tests around `app.runtime.server.create_app()` and route wiring.
- Add dedicated frontend tests for `live-feed.ts` and `dashboard-state.ts` behavior.
- Add integration tests for `app/cli/flow.py` interactive paths using input/output fixtures.
