"""Tests for identity resolution and merge precedence."""

import pytest
from identity import resolve_label, is_valid_mdns_label
from device_history import merge_scan


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


class TestResolveLabel:
    """Verify strict label resolution priority and no-guess policy."""

    EMPTY = dict(
        mdns_hostname=None,
        lockdownd_device_name=None,
        lockdownd_success=False,
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
