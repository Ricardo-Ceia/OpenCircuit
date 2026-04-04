# OpenCircuit Architecture

## Runtime Overview

- `scan_pipeline.py` contains network discovery and device fingerprinting pipeline.
- `main.py` is now a thin CLI-oriented entrypoint.
- `scanner.py` runs periodic background scans and keeps in-memory history.
- `server.py` exposes HTTP/WebSocket endpoints and serves static frontend assets.
- `web/ui` contains the Svelte dashboard, built into `web/static-svelte`.

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

- Convert `server.py` to app-factory + router modules to reduce global state.
- Move frontend transport/state lifecycle from `+page.svelte` into dedicated store/service files.
- Continue decomposing `scan_pipeline.py` into smaller modules (`ping`, `mdns`, `probe`, `identity_assembly`).
