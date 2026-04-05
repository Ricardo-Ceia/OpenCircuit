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
    assert isinstance(estimates[0]["distance_meters"], float)
    assert estimates[0]["distance_meters"] > 0
    assert estimates[0]["rssi_dbm"] == -63

    stored = service.get_estimate("AA:BB:CC:DD:EE:FF")
    assert stored is not None
    assert stored["room"] == "Office"
    assert isinstance(stored["distance_meters"], float)
    assert stored["rssi_dbm"] == -63


def test_estimate_online_devices_skips_without_ble_signal(monkeypatch, tmp_path):
    rooms_file = str(tmp_path / "rooms.json")
    fingerprints_file = str(tmp_path / "fingerprints.json")
    estimates_file = str(tmp_path / "estimates.json")

    monkeypatch.setattr("app.location.storage.LOCATION_ROOMS_FILE", rooms_file)
    monkeypatch.setattr("app.location.storage.LOCATION_FINGERPRINTS_FILE", fingerprints_file)
    monkeypatch.setattr("app.location.storage.LOCATION_ESTIMATES_FILE", estimates_file)

    service = LocationService()
    service.calibrate(
        room="Office",
        sensor_position="scanner",
        samples=[{"device_key": "AA:BB:CC:DD:EE:FF", "rssi_dbm": -62}],
    )

    result = service.estimate_online_devices(
        devices=[
            {
                "ip": "192.168.1.10",
                "status": "online",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ble_rssi_dbm": -63,
            },
            {
                "ip": "192.168.1.20",
                "status": "online",
                "mac": "11:22:33:44:55:66",
            },
            {
                "ip": "192.168.1.30",
                "status": "offline",
                "mac": "AA:AA:AA:AA:AA:AA",
                "ble_rssi_dbm": -70,
            },
        ],
        sensor_position="scanner",
    )

    assert result["online_count"] == 2
    assert result["estimated_count"] == 1
    assert result["skipped_count"] == 1
    assert result["estimated"][0]["device_key"] == "aa:bb:cc:dd:ee:ff"
    assert result["estimated"][0]["room"] == "Office"
    assert result["skipped"][0]["reason"] == "no_ble_signal"


def test_estimate_online_devices_accepts_ble_rssi_from_services(monkeypatch, tmp_path):
    rooms_file = str(tmp_path / "rooms.json")
    fingerprints_file = str(tmp_path / "fingerprints.json")
    estimates_file = str(tmp_path / "estimates.json")

    monkeypatch.setattr("app.location.storage.LOCATION_ROOMS_FILE", rooms_file)
    monkeypatch.setattr("app.location.storage.LOCATION_FINGERPRINTS_FILE", fingerprints_file)
    monkeypatch.setattr("app.location.storage.LOCATION_ESTIMATES_FILE", estimates_file)

    service = LocationService()
    service.calibrate(
        room="Office",
        sensor_position="scanner",
        samples=[{"device_key": "AA:BB:CC:DD:EE:FF", "rssi_dbm": -62}],
    )

    result = service.estimate_online_devices(
        devices=[
            {
                "ip": "192.168.1.10",
                "status": "online",
                "mac": "AA:BB:CC:DD:EE:FF",
                "services": ["http", "BLE:RSSI=-61"],
            }
        ],
        sensor_position="scanner",
    )

    assert result["estimated_count"] == 1
    assert result["estimated"][0]["rssi_dbm"] == -61
