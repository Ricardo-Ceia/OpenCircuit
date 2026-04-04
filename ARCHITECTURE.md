# OpenCircuit Architecture

## Runtime Overview

- `scan_pipeline.py` contains network discovery and device fingerprinting pipeline.
- `main.py` is now a thin runtime entrypoint.
- `cli_flow.py` contains interactive console display and identify/naming workflow.
- `scanner.py` runs periodic background scans and keeps in-memory history.
- `server.py` is now an app-factory composition layer.
- `server_auth.py` contains API/WS auth and origin policy.
- `server_ws.py` contains websocket lifecycle and broadcast manager.
- `server_routes.py` contains HTTP route handlers.
- `web/ui` contains the Svelte dashboard, built into `web/static-svelte`.
- Frontend live sync lifecycle is split into:
  - `web/ui/src/lib/live-feed.ts` for WS/poll/reconnect/heartbeat transport
  - `web/ui/src/lib/dashboard-state.ts` for payload-to-state transformations

## Backend Domain Contracts

- `models.py` defines typed scan models:
  - `LabelInfo`
  - `DeviceFingerprint`
  - `ScannedDevice`
- `ScannedDevice.to_record()` is the canonical conversion into legacy dictionary payloads.
- `settings.py` centralizes environment parsing and server/main runtime settings.
- `scan_pipeline.run_single_scan(...)` is the canonical scan orchestration API used by CLI and background scanner.

## Persistence

- `device_history.py` persists rolling scan state (`devices.json`).
- `known_devices.py` persists user-assigned names (`known_devices.json`).
- `secure_storage.py` provides atomic JSON writes and symlink protection.

## Quality Gates

- Backend tests: `python3 -m pytest -q`
- Frontend checks: `cd web/ui && npm run check`
- Frontend build: `cd web/ui && npm run build`

CI workflows:

- `.github/workflows/ci.yml` for tests/checks/build.
- `.github/workflows/security-audit.yml` for dependency vulnerability audits.

## Next Refactor Targets

- Continue decomposing `scan_pipeline.py` into smaller modules (`ping`, `mdns`, `probe`, `identity_assembly`).
- Introduce app-level integration tests around `create_app()` and route wiring.
- Add dedicated frontend tests for `live-feed.ts` and `dashboard-state.ts` behavior.
- Add integration tests for `cli_flow.py` interactive paths using input/output fixtures.
