from app.network.scan.mdns import parse_mdns_packet
from app.network.scan.probe import fetch_http_full


def test_parse_mdns_packet_handles_invalid_input_without_crash():
    payload = b"\x00\x00"
    result = parse_mdns_packet(payload, "192.168.1.5")
    assert result == []


def test_fetch_http_full_returns_default_shape_for_unreachable_host():
    result = fetch_http_full("203.0.113.9", port=65000, timeout=0.01)
    assert result["server"] is None
    assert result["title"] is None
    assert isinstance(result["headers"], dict)
    assert isinstance(result["body_snippet"], str)
