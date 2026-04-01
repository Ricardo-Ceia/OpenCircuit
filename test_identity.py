"""Tests for identity resolution and merge precedence."""

import pytest
import os
import json
from identity import resolve_label, is_valid_mdns_label, is_valid_rdns_label, _strip_local_tld, assign_stable_aliases
from device_history import merge_scan
from known_devices import load_known_devices, save_known_devices, get_known_name, set_known_name


class TestIsValidMdnsLabel:
    def test_valid_hostname(self):
        assert is_valid_mdns_label("johns-iphone.local") is True

    def test_generic_tv_hostname(self):
        assert is_valid_mdns_label("LGwebOSTV.local") is True

    def test_none(self):
        assert is_valid_mdns_label(None) is False

    def test_empty(self):
        assert is_valid_mdns_label("") is False

    def test_no_local_suffix(self):
        assert is_valid_mdns_label("some-host.example.com") is False

    def test_ip_shaped_ptr(self):
        assert is_valid_mdns_label("1.0.168.192.in-addr.arpa.local") is False

    def test_empty_after_suffix(self):
        assert is_valid_mdns_label(".local") is False

    def test_just_local(self):
        assert is_valid_mdns_label("local") is False

    def test_uuid_mdns_rejected(self):
        assert is_valid_mdns_label("5dc1fcd1-04aa-49a0-a124-dd374f7d36db.local") is False

    def test_uuid_case_insensitive(self):
        assert is_valid_mdns_label("5DC1FCD1-04AA-49A0-A124-DD374F7D36DB.local") is False


class TestIsValidRdnsLabel:
    def test_valid_home_hostname(self):
        assert is_valid_rdns_label("LGwebOSTV.home") is True

    def test_valid_laptop_hostname(self):
        assert is_valid_rdns_label("LAPTOP-U04CM6E5.home") is True

    def test_none(self):
        assert is_valid_rdns_label(None) is False

    def test_unknown_rejected(self):
        assert is_valid_rdns_label("unknown") is False

    def test_no_dot_rejected(self):
        assert is_valid_rdns_label("standalone") is False

    def test_uuid_rejected(self):
        assert is_valid_rdns_label("5dc1fcd1-04aa-49a0-a124-dd374f7d36db.home") is False

    def test_strip_home_tld(self):
        assert _strip_local_tld("LGwebOSTV.home") == "LGwebOSTV"

    def test_strip_lan_tld(self):
        assert _strip_local_tld("router.lan") == "router"

    def test_strip_preserves_case(self):
        assert _strip_local_tld("PT-GM0890XW.home") == "PT-GM0890XW"


class TestResolveLabel:
    """Verify strict label resolution priority and no-guess policy."""

    EMPTY = dict(
        mdns_hostname=None,
        lockdownd_device_name=None,
        lockdownd_success=False,
        rdns_hostname=None,
        upnp_friendly_name=None,
        upnp_device_type=None,
        ios_port_detected=False,
    )

    def _resolve(self, **overrides):
        return resolve_label(**{**self.EMPTY, **overrides})

    def test_lockdownd_wins(self):
        r = self._resolve(
            mdns_hostname="samsung-tv.local",
            lockdownd_device_name="John iPhone",
            lockdownd_success=True,
        )
        assert r["label"] == "John iPhone"
        assert r["label_source"] == "lockdownd"
        assert r["label_authoritative"] is True
        assert r["identity_status"] == "verified"

    def test_mdns_when_no_lockdownd(self):
        r = self._resolve(mdns_hostname="LGwebOSTV.local")
        assert r["label"] == "LGwebOSTV"
        assert r["label_source"] == "mdns"
        assert r["label_authoritative"] is True
        assert r["identity_status"] == "verified"

    def test_lockdownd_fail_falls_through_to_mdns(self):
        r = self._resolve(
            mdns_hostname="johns-iphone.local",
            lockdownd_device_name="John iPhone",
            lockdownd_success=False,
        )
        assert r["label"] == "johns-iphone"
        assert r["label_source"] == "mdns"

    def test_upnp_friendly_name(self):
        r = self._resolve(upnp_friendly_name="Hitron HUB5")
        assert r["label"] == "Hitron HUB5"
        assert r["label_source"] == "upnp"
        assert r["label_authoritative"] is False
        assert r["identity_status"] == "identified"

    def test_upnp_not_used_when_mdns_available(self):
        r = self._resolve(
            mdns_hostname="router.local",
            upnp_friendly_name="Hitron Technologies HUB5",
        )
        assert r["label_source"] == "mdns"
        assert r["label_authoritative"] is True

    def test_rdns_hostname(self):
        r = self._resolve(rdns_hostname="LGwebOSTV.home")
        assert r["label"] == "LGwebOSTV"
        assert r["label_source"] == "rdns"
        assert r["label_authoritative"] is False
        assert r["identity_status"] == "identified"

    def test_rdns_laptop(self):
        r = self._resolve(rdns_hostname="LAPTOP-U04CM6E5.home")
        assert r["label"] == "LAPTOP-U04CM6E5"
        assert r["label_source"] == "rdns"

    def test_rdns_not_used_when_mdns_available(self):
        r = self._resolve(
            mdns_hostname="tv.local",
            rdns_hostname="LGwebOSTV.home",
        )
        assert r["label_source"] == "mdns"

    def test_rdns_wins_over_upnp(self):
        r = self._resolve(
            rdns_hostname="LGwebOSTV.home",
            upnp_friendly_name="HUB5",
        )
        assert r["label_source"] == "rdns"
        assert r["label"] == "LGwebOSTV"

    def test_rdns_unknown_rejected(self):
        r = self._resolve(rdns_hostname="unknown")
        assert r["identity_status"] == "unidentified"

    def test_ios_port_only_gives_unidentified_type(self):
        r = self._resolve(ios_port_detected=True)
        assert r["label"] == "Unidentified Apple iOS Device"
        assert r["label_source"] == "device_type"
        assert r["label_authoritative"] is False
        assert r["identity_status"] == "unidentified"

    def test_upnp_device_type_unidentified(self):
        r = self._resolve(upnp_device_type="MediaRenderer")
        assert r["label"] == "Unidentified MediaRenderer"
        assert r["identity_status"] == "unidentified"

    def test_nothing_gives_unidentified_device(self):
        r = self._resolve()
        assert r["label"] == "Unidentified device"
        assert r["label_source"] == "unidentified"
        assert r["label_authoritative"] is False
        assert r["identity_status"] == "unidentified"

    def test_ios_port_type_overridden_by_upnp_type(self):
        r = self._resolve(
            upnp_device_type="InternetGatewayDevice",
            ios_port_detected=True,
        )
        assert r["label"] == "Unidentified InternetGatewayDevice"

    def test_upnp_friendly_name_strips_whitespace(self):
        r = self._resolve(upnp_friendly_name="  LG TV  ")
        assert r["label"] == "LG TV"

    def test_empty_upnp_friendly_name_treated_as_none(self):
        r = self._resolve(upnp_friendly_name="   ")
        assert r["identity_status"] == "unidentified"

    def test_uuid_mdns_falls_through(self):
        r = self._resolve(mdns_hostname="5dc1fcd1-04aa-49a0-a124-dd374f7d36db.local")
        # UUID mDNS name is not a real label — falls through
        assert r["identity_status"] == "unidentified"
        assert r["label"] == "Unidentified device"
        assert r["label_authoritative"] is False

    def test_uuid_mdns_upnp_used_instead(self):
        r = self._resolve(
            mdns_hostname="5dc1fcd1-04aa-49a0-a124-dd374f7d36db.local",
            upnp_friendly_name="Arcadyan Extender",
        )
        assert r["label"] == "Arcadyan Extender"
        assert r["label_source"] == "upnp"


class TestMergePrecedence:
    """Test that merge_scan respects label authority."""

    def _make_device(self, ip, label, label_source, label_authoritative, identity_status):
        return {
            "ip": ip,
            "label": label,
            "label_source": label_source,
            "label_authoritative": label_authoritative,
            "identity_status": identity_status,
            "hostname": "test.local",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": None,
            "source": "test",
            "services": [],
            "fingerprint": {},
        }

    def test_authoritative_not_overwritten_by_non_authoritative(self):
        history = {}
        scan1 = [self._make_device("192.168.1.10", "John iPhone", "lockdownd", True, "verified")]
        merge_scan(scan1, history, retention_hours=1)
        assert history["192.168.1.10"]["label"] == "John iPhone"
        assert history["192.168.1.10"]["label_authoritative"] is True

        scan2 = [self._make_device("192.168.1.10", "Unidentified Apple iOS Device", "device_type", False, "unidentified")]
        merge_scan(scan2, history, retention_hours=1)
        # Authoritative label preserved
        assert history["192.168.1.10"]["label"] == "John iPhone"
        assert history["192.168.1.10"]["label_authoritative"] is True

    def test_authoritative_overwrites_non_authoritative(self):
        history = {}
        scan1 = [self._make_device("192.168.1.10", "Unidentified Apple iOS Device", "device_type", False, "unidentified")]
        merge_scan(scan1, history, retention_hours=1)

        scan2 = [self._make_device("192.168.1.10", "John iPhone", "lockdownd", True, "verified")]
        merge_scan(scan2, history, retention_hours=1)
        assert history["192.168.1.10"]["label"] == "John iPhone"
        assert history["192.168.1.10"]["identity_status"] == "verified"

    def test_new_device_gets_label_from_scan(self):
        history = {}
        scan = [self._make_device("192.168.1.20", "Living Room TV", "mdns", True, "verified")]
        merge_scan(scan, history, retention_hours=1)
        assert history["192.168.1.20"]["label"] == "Living Room TV"
        assert history["192.168.1.20"]["label_authoritative"] is True


class TestKnownNamePriority:
    """Test that user-assigned names win over all automatic labels."""

    EMPTY = dict(
        mdns_hostname=None,
        lockdownd_device_name=None,
        lockdownd_success=False,
        rdns_hostname=None,
        upnp_friendly_name=None,
        upnp_device_type=None,
        ios_port_detected=False,
        known_name=None,
    )

    def _resolve(self, **overrides):
        return resolve_label(**{**self.EMPTY, **overrides})

    def test_known_name_wins_over_lockdownd(self):
        r = self._resolve(
            known_name="Ricardo's iPhone",
            lockdownd_device_name="John iPhone",
            lockdownd_success=True,
        )
        assert r["label"] == "Ricardo's iPhone"
        assert r["label_source"] == "known"
        assert r["identity_status"] == "claimed"
        assert r["label_authoritative"] is True

    def test_known_name_wins_over_mdns(self):
        r = self._resolve(
            known_name="Living Room TV",
            mdns_hostname="LGwebOSTV.local",
        )
        assert r["label"] == "Living Room TV"
        assert r["label_source"] == "known"

    def test_known_name_none_falls_through(self):
        r = self._resolve(known_name=None, mdns_hostname="LGwebOSTV.local")
        assert r["label_source"] == "mdns"

    def test_known_name_empty_falls_through(self):
        r = self._resolve(known_name="", mdns_hostname="LGwebOSTV.local")
        assert r["label_source"] == "mdns"

    def test_known_name_whitespace_falls_through(self):
        r = self._resolve(known_name="   ", mdns_hostname="LGwebOSTV.local")
        assert r["label_source"] == "mdns"


class TestStableAliases:
    """Test that same-type devices get stable numbered aliases."""

    def test_two_ios_devices_get_aliases(self):
        devices = [
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:00:00"},
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:01:00"},
        ]
        result = assign_stable_aliases(devices)
        assert result[0]["label"] == "Apple iOS Device #1"
        assert result[1]["label"] == "Apple iOS Device #2"

    def test_single_device_no_alias(self):
        devices = [
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:00:00"},
        ]
        result = assign_stable_aliases(devices)
        assert result[0]["label"] == "Unidentified Apple iOS Device"

    def test_verified_devices_not_aliased(self):
        devices = [
            {"label": "LGwebOSTV", "identity_status": "verified",
             "first_seen": "2026-04-01T10:00:00"},
            {"label": "LGwebOSTV", "identity_status": "verified",
             "first_seen": "2026-04-01T10:01:00"},
        ]
        result = assign_stable_aliases(devices)
        # Verified devices keep their names
        assert result[0]["label"] == "LGwebOSTV"
        assert result[1]["label"] == "LGwebOSTV"

    def test_mixed_types_aliased_separately(self):
        devices = [
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:00:00"},
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:01:00"},
            {"label": "Unidentified device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:02:00"},
        ]
        result = assign_stable_aliases(devices)
        assert result[0]["label"] == "Apple iOS Device #1"
        assert result[1]["label"] == "Apple iOS Device #2"
        # Third device is unique type, no alias
        assert result[2]["label"] == "Unidentified device"

    def test_stable_ordering_by_first_seen(self):
        devices = [
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:05:00"},
            {"label": "Unidentified Apple iOS Device", "identity_status": "unidentified",
             "first_seen": "2026-04-01T10:00:00"},
        ]
        result = assign_stable_aliases(devices)
        # Earlier first_seen = #1
        assert result[1]["label"] == "Apple iOS Device #1"  # sorted by first_seen
        assert result[0]["label"] == "Apple iOS Device #2"


class TestKnownDevices:
    """Test known_devices.json persistence."""

    def test_set_and_get(self, tmp_path, monkeypatch):
        test_file = str(tmp_path / "known.json")
        monkeypatch.setattr("known_devices.KNOWN_DEVICES_FILE", test_file)

        set_known_name("aa:bb:cc:dd:ee:ff", "Ricardo's iPhone")
        assert get_known_name("aa:bb:cc:dd:ee:ff") == "Ricardo's iPhone"

    def test_case_insensitive(self, tmp_path, monkeypatch):
        test_file = str(tmp_path / "known.json")
        monkeypatch.setattr("known_devices.KNOWN_DEVICES_FILE", test_file)

        set_known_name("AA:BB:CC:DD:EE:FF", "Test")
        assert get_known_name("aa:bb:cc:dd:ee:ff") == "Test"

    def test_unknown_mac_returns_none(self, tmp_path, monkeypatch):
        test_file = str(tmp_path / "known.json")
        monkeypatch.setattr("known_devices.KNOWN_DEVICES_FILE", test_file)

        assert get_known_name("unknown") is None
        assert get_known_name("") is None
        assert get_known_name(None) is None

    def test_missing_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("known_devices.KNOWN_DEVICES_FILE", str(tmp_path / "nope.json"))
        assert get_known_name("aa:bb:cc:dd:ee:ff") is None

    def test_persist_across_load(self, tmp_path, monkeypatch):
        test_file = str(tmp_path / "known.json")
        monkeypatch.setattr("known_devices.KNOWN_DEVICES_FILE", test_file)

        set_known_name("aa:bb:cc:dd:ee:ff", "Living Room TV")
        # Simulate reload
        data = load_known_devices()
        assert data["aa:bb:cc:dd:ee:ff"]["name"] == "Living Room TV"

