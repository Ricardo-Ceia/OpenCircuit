from app.location.engine import aggregate_calibration_samples, estimate_room


def test_aggregate_calibration_samples_groups_by_room_position_and_device():
    samples = [
        {"room": "Office", "sensor_position": "desk", "device_key": "AA:BB", "rssi_dbm": -62},
        {"room": "Office", "sensor_position": "desk", "device_key": "aa:bb", "rssi_dbm": -66},
        {"room": "Kitchen", "sensor_position": "desk", "device_key": "aa:bb", "rssi_dbm": -79},
    ]

    fingerprints = aggregate_calibration_samples(samples)
    assert len(fingerprints) == 2
    office = next(entry for entry in fingerprints if entry["room"] == "Office")
    assert office["device_key"] == "aa:bb"
    assert office["sample_count"] == 2


def test_estimate_room_returns_best_match_and_confidence():
    fingerprints = [
        {"room": "Office", "sensor_position": "desk", "device_key": "aa:bb", "rssi_median": -63.0, "sample_count": 5},
        {"room": "Kitchen", "sensor_position": "desk", "device_key": "aa:bb", "rssi_median": -78.0, "sample_count": 5},
    ]

    result = estimate_room(
        sample={"device_key": "AA:BB", "sensor_position": "desk", "rssi_dbm": -64},
        fingerprints=fingerprints,
    )

    assert result is not None
    assert result["room"] == "Office"
    assert result["estimated_via"] == "sms-fingerprint"
    assert 0.0 <= result["confidence"] <= 1.0
