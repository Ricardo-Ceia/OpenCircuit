from app.location.service import LocationService


def test_calibrate_and_estimate_roundtrip(monkeypatch, tmp_path):
    rooms_file = str(tmp_path / "rooms.json")
    fingerprints_file = str(tmp_path / "fingerprints.json")
    estimates_file = str(tmp_path / "estimates.json")

    monkeypatch.setattr("app.location.storage.LOCATION_ROOMS_FILE", rooms_file)
    monkeypatch.setattr("app.location.storage.LOCATION_FINGERPRINTS_FILE", fingerprints_file)
    monkeypatch.setattr("app.location.storage.LOCATION_ESTIMATES_FILE", estimates_file)

    service = LocationService()

    calibration_result = service.calibrate(
        room="Office",
        sensor_position="desk",
        samples=[
            {"device_key": "AA:BB:CC:DD:EE:FF", "rssi_dbm": -62},
            {"device_key": "AA:BB:CC:DD:EE:FF", "rssi_dbm": -65},
        ],
    )
    assert calibration_result["fingerprint_count"] == 1

    estimates = service.estimate(
        sensor_position="desk",
        samples=[{"device_key": "aa:bb:cc:dd:ee:ff", "rssi_dbm": -63}],
    )
    assert len(estimates) == 1
    assert estimates[0]["room"] == "Office"

    stored = service.get_estimate("AA:BB:CC:DD:EE:FF")
    assert stored is not None
    assert stored["room"] == "Office"
