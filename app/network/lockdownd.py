import socket
import struct
import os
import logging
from datetime import datetime

from app.storage.secure_storage import read_json, write_json_atomic

log = logging.getLogger(__name__)

LOCKDOWND_PORT = 62078
PAIR_RECORDS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "pair_records",
)

# Comprehensive iPhone model identifier mapping
IPHONE_MODELS = {
    # iPhone 16 series
    "iPhone17,1": "iPhone 16 Pro Max",
    "iPhone17,2": "iPhone 16 Pro",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    # iPhone 15 series
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone15,2": "iPhone 15",
    "iPhone15,3": "iPhone 15 Plus",
    # iPhone 14 series
    "iPhone14,5": "iPhone 14",
    "iPhone14,6": "iPhone 14 Plus",
    "iPhone14,2": "iPhone 14 Pro",
    "iPhone14,3": "iPhone 14 Pro Max",
    # iPhone 13 series
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    # iPhone 12 series
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    # iPhone SE
    "iPhone12,8": "iPhone SE (2nd gen)",
    "iPhone14,6": "iPhone SE (3rd gen)",
    # iPhone 11 series
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    # iPhone XS/XR
    "iPhone11,2": "iPhone XS",
    "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",
    "iPhone11,8": "iPhone XR",
    # iPhone X
    "iPhone10,3": "iPhone X",
    "iPhone10,6": "iPhone X",
    # iPhone 8
    "iPhone10,1": "iPhone 8",
    "iPhone10,4": "iPhone 8",
    "iPhone10,2": "iPhone 8 Plus",
    "iPhone10,5": "iPhone 8 Plus",
    # iPhone 7
    "iPhone9,1": "iPhone 7",
    "iPhone9,3": "iPhone 7",
    "iPhone9,2": "iPhone 7 Plus",
    "iPhone9,4": "iPhone 7 Plus",
    # iPhone 6s
    "iPhone8,1": "iPhone 6s",
    "iPhone8,2": "iPhone 6s Plus",
    "iPhone8,4": "iPhone SE (1st gen)",
    # iPhone 6
    "iPhone7,2": "iPhone 6",
    "iPhone7,1": "iPhone 6 Plus",
}


def _get_pair_records_dir() -> str:
    """Get path to pair records directory."""
    if os.path.islink(PAIR_RECORDS_DIR):
        raise OSError(f"Refusing symlink directory: {PAIR_RECORDS_DIR}")
    os.makedirs(PAIR_RECORDS_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(PAIR_RECORDS_DIR, 0o700)
    except OSError:
        pass
    return PAIR_RECORDS_DIR


def _get_system_buid() -> str:
    """Generate or load system BUID."""
    buid_path = os.path.join(_get_pair_records_dir(), "system_buid.json")
    if os.path.exists(buid_path):
        existing = read_json(buid_path, default={})
        if isinstance(existing, dict):
            buid = existing.get("SystemBUID")
            if isinstance(buid, str) and buid:
                return buid

    # Generate a random BUID
    import uuid
    buid = str(uuid.uuid4()).upper()
    write_json_atomic(buid_path, {"SystemBUID": buid}, indent=2)
    return buid


def _get_pair_record(ip: str) -> dict | None:
    """Load pair record for a specific device."""
    # Use IP as identifier for simplicity (in production, use WiFi MAC or UDID)
    record_path = os.path.join(_get_pair_records_dir(), f"{ip.replace('.', '_')}.json")
    if os.path.exists(record_path):
        data = read_json(record_path, default=None)
        if isinstance(data, dict):
            return data
    return None


def _save_pair_record(ip: str, record: dict):
    """Save pair record for a specific device."""
    record_path = os.path.join(_get_pair_records_dir(), f"{ip.replace('.', '_')}.json")
    write_json_atomic(record_path, record, indent=2)


def _send_plist(sock: socket.socket, plist_xml: bytes):
    """Send a plist with 4-byte big-endian length prefix."""
    length = len(plist_xml)
    header = struct.pack(">I", length)
    sock.sendall(header + plist_xml)


def _receive_plist(sock: socket.socket, timeout: float = 2.0) -> bytes | None:
    """Receive a plist with 4-byte big-endian length prefix."""
    sock.settimeout(timeout)
    
    # Read length header
    header = b""
    while len(header) < 4:
        try:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        except (socket.timeout, OSError):
            return None
    
    length = struct.unpack(">I", header)[0]
    if length > 1000000:  # Sanity check (1MB max)
        return None
    
    # Read plist data
    data = b""
    while len(data) < length:
        try:
            chunk = sock.recv(min(8192, length - len(data)))
            if not chunk:
                return None
            data += chunk
        except (socket.timeout, OSError):
            return None
    
    return data


def _build_plist_dict(**kwargs) -> str:
    """Build a simple XML plist dictionary."""
    items = []
    for key, value in kwargs.items():
        if isinstance(value, bool):
            items.append(f"<key>{key}</key><{'true' if value else 'false'}/>")
        elif isinstance(value, int):
            items.append(f"<key>{key}</key><integer>{value}</integer>")
        elif isinstance(value, str):
            items.append(f"<key>{key}</key><string>{value}</string>")
        elif isinstance(value, bytes):
            import base64
            encoded = base64.b64encode(value).decode('ascii')
            items.append(f"<key>{key}</key><data>{encoded}</data>")
    
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n' + '\n'.join(items) + '\n</dict>\n'
        '</plist>'
    )


def _parse_plist_value(xml_bytes: bytes, key: str) -> str | None:
    """Extract a string value from a plist XML response."""
    import re
    try:
        xml_str = xml_bytes.decode('utf-8', errors='ignore')
        # Find the key, then get the next string value
        pattern = f'<key>{key}</key>\\s*<string>(.*?)</string>'
        match = re.search(pattern, xml_str, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
    except (UnicodeDecodeError, re.error):
        pass
    return None


def _parse_plist_type(xml_bytes: bytes) -> str | None:
    """Extract the Type field from a QueryType response."""
    return _parse_plist_value(xml_bytes, "Type")


def _parse_plist_result(xml_bytes: bytes) -> str | None:
    """Extract the Result field from a response."""
    return _parse_plist_value(xml_bytes, "Result")


def _parse_plist_error(xml_bytes: bytes) -> str | None:
    """Extract the Error field from a response."""
    return _parse_plist_value(xml_bytes, "Error")


def _parse_plist_session_id(xml_bytes: bytes) -> str | None:
    """Extract the SessionID field from a response."""
    return _parse_plist_value(xml_bytes, "SessionID")


def _parse_plist_enable_ssl(xml_bytes: bytes) -> bool:
    """Extract the EnableSessionSSL field from a response."""
    import re
    try:
        xml_str = xml_bytes.decode('utf-8', errors='ignore')
        if '<true/>' in xml_str and 'EnableSessionSSL' in xml_str:
            return True
    except UnicodeDecodeError:
        pass
    return False


def _parse_plist_value_field(xml_bytes: bytes) -> str | None:
    """Extract the Value field from a GetValue response."""
    return _parse_plist_value(xml_bytes, "Value")


def query_type(ip: str, timeout: float = 2.0) -> str | None:
    """Query lockdown service type."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, LOCKDOWND_PORT))
        
        # First send Hello with protocol version 2 (required by modern iOS)
        hello = _build_plist_dict(
            Request="Hello",
            Label="OpenCircuitScanner",
            ProtocolVersion="2"
        )
        _send_plist(sock, hello.encode('utf-8'))
        
        hello_response = _receive_plist(sock, timeout)
        if not hello_response:
            sock.close()
            return None
        
        # Now send QueryType
        request = _build_plist_dict(Request="QueryType")
        _send_plist(sock, request.encode('utf-8'))
        
        response = _receive_plist(sock, timeout)
        sock.close()
        
        if response:
            return _parse_plist_type(response)
    except OSError as exc:
        log.debug(f"Lockdownd query_type failed for {ip}: {exc}")
    
    return None


def get_value(ip: str, key: str, session_id: str | None = None, timeout: float = 2.0) -> str | None:
    """Get a value from the device."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, LOCKDOWND_PORT))
        
        request_dict = {"Request": "GetValue", "Key": key}
        if session_id:
            request_dict["SessionID"] = session_id
        
        request = _build_plist_dict(**request_dict)
        _send_plist(sock, request.encode('utf-8'))
        
        response = _receive_plist(sock, timeout)
        sock.close()
        
        if response:
            return _parse_plist_value_field(response)
    except OSError as e:
        log.debug(f"Lockdownd get_value({key}) failed for {ip}: {e}")
    
    return None


def get_ios_device_info(ip: str, timeout: float = 5.0) -> dict | None:
    """
    Full lockdownd handshake to get iOS device info.
    
    Returns dict with device_name, model, model_identifier, ios_version, udid
    or None if the device is locked or unreachable.
    """
    result: dict[str, str | None] = {
        "device_name": None,
        "model": None,
        "model_identifier": None,
        "ios_version": None,
        "udid": None,
    }
    
    try:
        # Step 1: Verify lockdown service
        service_type = query_type(ip, timeout=2.0)
        if service_type != "com.apple.mobile.lockdown":
            return None
        
        # Step 2: Try to get values without session (works on some iOS versions)
        for key in ["DeviceName", "ProductType", "ProductVersion", "UniqueDeviceID"]:
            value = get_value(ip, key)
            if value:
                if key == "DeviceName":
                    result["device_name"] = value
                elif key == "ProductType":
                    result["model_identifier"] = value
                    result["model"] = IPHONE_MODELS.get(value, value)
                elif key == "ProductVersion":
                    result["ios_version"] = value
                elif key == "UniqueDeviceID":
                    result["udid"] = value
        
        if result["device_name"]:
            return result
        
        # Step 3: Try with Hello handshake (some devices allow GetValue after Hello)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, LOCKDOWND_PORT))
        
        # Send Hello with protocol version 2
        hello = _build_plist_dict(
            Request="Hello",
            Label="OpenCircuitScanner",
            ProtocolVersion="2"
        )
        _send_plist(sock, hello.encode('utf-8'))
        
        response = _receive_plist(sock, timeout)
        
        if response:
            # Try getting values after Hello
            for key in ["DeviceName", "ProductType", "ProductVersion", "UniqueDeviceID"]:
                request = _build_plist_dict(
                    Request="GetValue",
                    Key=key,
                    Label="OpenCircuitScanner"
                )
                _send_plist(sock, request.encode('utf-8'))
                resp = _receive_plist(sock, timeout)
                if resp:
                    value = _parse_plist_value_field(resp)
                    if value:
                        if key == "DeviceName":
                            result["device_name"] = value
                        elif key == "ProductType":
                            result["model_identifier"] = value
                            result["model"] = IPHONE_MODELS.get(value, value)
                        elif key == "ProductVersion":
                            result["ios_version"] = value
                        elif key == "UniqueDeviceID":
                            result["udid"] = value
        
        sock.close()
        
        # Return result if we got at least the device name
        if result["device_name"]:
            return result
        
    except OSError as exc:
        log.debug(f"Lockdownd handshake failed for {ip}: {exc}")

    return None


def get_model_display_name(model_identifier: str) -> str:
    """Get human-readable model name from identifier."""
    return IPHONE_MODELS.get(model_identifier, model_identifier)
