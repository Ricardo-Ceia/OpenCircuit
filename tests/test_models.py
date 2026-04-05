from app.domain.models import DeviceFingerprint, LabelInfo, ScannedDevice


def test_device_fingerprint_from_raw_preserves_unknown_fields():
    raw = {
        "manufacturer": "Acme",
        "model": "Router X",
        "friendly_name": "Home Router",
        "device_type": "InternetGatewayDevice",
        "model_number": "X100",
        "firmware": "1.2.3",
    }

    fp = DeviceFingerprint.from_raw(raw)

    assert fp.manufacturer == "Acme"
    assert fp.model == "Router X"
    assert fp.extra == {"firmware": "1.2.3"}


def test_scanned_device_to_record_uses_label_contract():
    device = ScannedDevice(
        ip="192.168.1.9",
        label_info=LabelInfo(
            label="Living Room TV",
            label_source="mdns",
            label_authoritative=True,
            identity_status="verified",
        ),
        hostname="living-room.local",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="LG",
        source_channels=["ping", "mdns"],
    )

    record = device.to_record()

    assert record["label"] == "Living Room TV"
    assert record["label_source"] == "mdns"
    assert record["label_authoritative"] is True
    assert record["identity_status"] == "verified"
    assert record["source"] == "ping+mdns"


def test_scanned_device_to_record_includes_distance_fields():
    device = ScannedDevice(
        ip="192.168.1.12",
        label_info=LabelInfo(
            label="Phone",
            label_source="known",
            label_authoritative=True,
            identity_status="claimed",
        ),
        hostname="phone.local",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="Apple",
        source_channels=["ping"],
        location_hint="Office",
        location_confidence=0.66,
        distance_meters=1.45,
        rssi_dbm=-63,
        estimated_via="sms-fingerprint",
    )

    record = device.to_record()

    assert record["location_hint"] == "Office"
    assert record["location_confidence"] == 0.66
    assert record["distance_meters"] == 1.45
    assert record["rssi_dbm"] == -63
    assert record["estimated_via"] == "sms-fingerprint"
