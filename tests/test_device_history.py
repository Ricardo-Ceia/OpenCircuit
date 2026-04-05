from datetime import datetime, timedelta

from app.storage.device_history import clean_expired_devices, merge_scan


def _iso_hours_ago(hours: int) -> str:
    return (datetime.now() - timedelta(hours=hours)).isoformat()


def test_clean_expired_devices_ignores_invalid_timestamps():
    history = {
        "192.168.1.10": {
            "ip": "192.168.1.10",
            "last_seen": "not-a-date",
            "status": "offline",
        },
        "192.168.1.11": {
            "ip": "192.168.1.11",
            "last_seen": _iso_hours_ago(4),
            "status": "offline",
        },
    }

    removed = clean_expired_devices(history, retention_hours=1)

    assert removed == ["192.168.1.11"]
    assert "192.168.1.10" in history


def test_merge_scan_preserves_authoritative_label_over_non_authoritative_update():
    history: dict = {
        "192.168.1.20": {
            "ip": "192.168.1.20",
            "label": "Alice iPhone",
            "label_source": "lockdownd",
            "label_authoritative": True,
            "identity_status": "verified",
            "hostname": "alice.local",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": "Apple",
            "sources": ["ping"],
            "services": [],
            "fingerprint": {},
            "first_seen": _iso_hours_ago(1),
            "last_seen": _iso_hours_ago(1),
            "status": "online",
        }
    }

    current_scan = [
        {
            "ip": "192.168.1.20",
            "label": "Unidentified Apple iOS Device",
            "label_source": "device_type",
            "label_authoritative": False,
            "identity_status": "unidentified",
            "hostname": "unknown",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": "Apple",
            "source": "ping+probe",
            "services": ["lockdownd (port 62078)"],
            "fingerprint": {},
            "location_hint": "Office",
            "location_confidence": 0.75,
            "distance_meters": 2.4,
            "rssi_dbm": -63,
            "estimated_via": "sms-fingerprint",
        }
    ]

    merge_scan(current_scan, history, retention_hours=24)

    device = history["192.168.1.20"]
    assert device["label"] == "Alice iPhone"
    assert device["label_source"] == "lockdownd"
    assert device["identity_status"] == "verified"
    assert device["status"] == "online"
    assert device["location_hint"] == "Office"
    assert device["distance_meters"] == 2.4
