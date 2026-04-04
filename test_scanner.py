from __future__ import annotations

from scanner import BackgroundScanner


def _scan_result(ip: str) -> dict:
    return {
        "ip": ip,
        "label": "Device",
        "label_source": "mdns",
        "label_authoritative": True,
        "identity_status": "verified",
        "hostname": "device.local",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Acme",
        "services": ["ping"],
        "fingerprint": {},
        "source": "ping",
    }


def test_background_scanner_uses_injected_scan_runner(monkeypatch):
    monkeypatch.setattr("scanner.load_history", lambda: {})

    persisted_history: dict[str, dict] = {}

    def fake_save_history(history: dict):
        persisted_history.clear()
        persisted_history.update(history)

    monkeypatch.setattr("scanner.save_history", fake_save_history)

    captured_merge_inputs = []

    def fake_merge_scan(current_scan: list[dict], history: dict):
        captured_merge_inputs.append(current_scan)
        history["192.168.1.10"] = _scan_result("192.168.1.10")
        return history

    monkeypatch.setattr("scanner.merge_scan", fake_merge_scan)

    calls = []

    def fake_scan_runner(subnet: str, timeout: int) -> list[dict]:
        calls.append((subnet, timeout))
        return [_scan_result("192.168.1.10")]

    scanner = BackgroundScanner(
        subnet="192.168.1.0/24",
        mdns_timeout=9,
        arp_interval=30,
        scan_runner=fake_scan_runner,
    )

    scanner._do_scan()

    assert calls == [("192.168.1.0/24", 5)]
    assert len(captured_merge_inputs) == 1
    assert persisted_history["192.168.1.10"]["ip"] == "192.168.1.10"


def test_background_scanner_notifies_callbacks_with_snapshot(monkeypatch):
    monkeypatch.setattr("scanner.load_history", lambda: {})
    monkeypatch.setattr("scanner.save_history", lambda history: None)
    monkeypatch.setattr("scanner.merge_scan", lambda current_scan, history: {"192.168.1.20": _scan_result("192.168.1.20")})

    scanner = BackgroundScanner(
        subnet="192.168.1.0/24",
        scan_runner=lambda subnet, timeout: [_scan_result("192.168.1.20")],
    )

    observed: list[list[dict]] = []
    scanner.register_callback(lambda devices: observed.append(devices))

    scanner._do_scan()

    assert len(observed) == 1
    assert observed[0][0]["ip"] == "192.168.1.20"
