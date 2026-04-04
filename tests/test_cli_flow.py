from app.cli.flow import build_clue, is_device_offline


def test_build_clue_prefers_fingerprint_brand_and_model():
    device = {
        "fingerprint": {"manufacturer": "Apple", "model": "iPhone"},
        "vendor": "Unknown Vendor",
    }
    assert build_clue(device) == "Apple iPhone"


def test_build_clue_falls_back_to_vendor():
    device = {"fingerprint": {}, "vendor": "Samsung"}
    assert build_clue(device) == "Samsung"


def test_is_device_offline_returns_true_when_all_pings_fail():
    calls: list[str] = []

    def fake_ping(ip: str) -> bool:
        calls.append(ip)
        return False

    def fake_sleep(_seconds: float):
        return

    assert is_device_offline("192.168.1.2", retries=3, ping_fn=fake_ping, sleep_fn=fake_sleep) is True
    assert len(calls) == 3


def test_is_device_offline_returns_false_when_ping_recovers():
    states = iter([False, True])

    def fake_ping(_ip: str) -> bool:
        return next(states)

    def fake_sleep(_seconds: float):
        return

    assert is_device_offline("192.168.1.3", retries=3, ping_fn=fake_ping, sleep_fn=fake_sleep) is False
