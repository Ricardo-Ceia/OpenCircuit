import logging
import time
import threading
import sys
from device_history import format_last_seen, get_history_as_list, get_history_stats, _get_retention_hours
from identity import assign_stable_aliases
from known_devices import set_known_name
from scan_pipeline import ping_ip, run_single_scan

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

def _build_clue(d: dict) -> str:
    """Build a plain-English clue string for a device."""
    clues = []
    fingerprint = d.get("fingerprint", {})
    vendor = d.get("vendor")

    # Brand from fingerprint or vendor
    manufacturer = fingerprint.get("manufacturer")
    model = fingerprint.get("model")
    if manufacturer and model:
        clues.append(f"{manufacturer} {model}")
    elif manufacturer:
        clues.append(manufacturer)
    elif vendor:
        clues.append(vendor)

    return " · ".join(clues)


def print_display(history: dict, scan_count: int):
    """Print the device table."""
    devices = get_history_as_list(history)
    stats = get_history_stats(history)
    retention = _get_retention_hours()

    # Apply stable aliases for same-type devices
    devices = assign_stable_aliases(devices)

    # Sort: claimed first, then verified, identified, unidentified; online before offline
    _identity_order = {"claimed": 0, "verified": 1, "identified": 2, "unidentified": 3}
    _status_order = {"online": 0, "offline": 1}
    devices.sort(key=lambda d: (
        _identity_order.get(d.get("identity_status", "unidentified"), 9),
        _status_order.get(d.get("status", "offline"), 9),
        d.get("first_seen", ""),
    ))

    # Clear screen (no subprocess — avoids ConPTY input buffer disruption on Windows)
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    print("=" * 140)
    print(f"  NETWORK SCANNER - Scan #{scan_count} | Retention: {retention}h | Press Ctrl+C to exit")
    print("=" * 140)
    print(f"\n{'Label':<30} {'Clue':<28} {'Identity':<12} {'Status':<10} {'Last Seen':<12} {'IP':<18} {'Scans'}")
    print("-" * 140)

    for d in devices:
        label = d.get('label', d.get('hostname', 'Unidentified device'))
        identity = d.get('identity_status', 'unidentified')
        status = "ONLINE" if d.get('status') == 'online' else "OFFLINE"
        last_seen = format_last_seen(d.get('last_seen', ''))
        sources = d.get('sources', d.get('source', []))
        if isinstance(sources, str):
            sources = sources.split('+') if sources else []
        clue = _build_clue(d)

        print(f"{label:<30} {clue:<28} {identity:<12} {status:<10} {last_seen:<12} {d['ip']:<18} {'+'.join(sources)}")

    print("-" * 140)
    print(f"  Total: {stats['total']} | Online: {stats['online']} | Offline: {stats['offline']} | Verified: {stats['verified']} | Unidentified: {stats['unidentified']}")

    # Show unnamed device hint
    unnamed_count = sum(
        1 for d in devices
        if d.get("identity_status") == "unidentified" and d.get("status") == "online"
    )
    if unnamed_count > 0:
        print(f"  {unnamed_count} unnamed device(s) — type 'i' + Enter to name them")

    print()

def _is_device_offline(ip: str, retries: int = 2) -> bool:
    """Check if a device is offline by pinging it."""
    for _ in range(retries):
        if ping_ip(ip):
            return False
        time.sleep(0.3)
    return True


def _run_identify_flow(subnet: str):
    """Auto-detect identify flow. User disconnects Wi-Fi, system detects which device."""
    print("\n  Scanning network...\n")
    scan_results = run_single_scan(subnet, mdns_timeout=5)

    # Filter to only online unnamed devices with known MACs
    unnamed = []
    for d in scan_results:
        if d.get("identity_status") in ("claimed",):
            continue
        if d.get("label_source") == "known":
            continue
        if d.get("status") != "online":
            continue
        mac = d.get("mac", "unknown")
        if mac == "unknown":
            continue
        unnamed.append(d)

    if not unnamed:
        print("  No online unnamed devices found.\n")
        return

    assign_stable_aliases(unnamed)

    while unnamed:
        print(f"  {'Unnamed devices':}")
        print(f"  {'-' * 40}")
        for i, d in enumerate(unnamed, 1):
            label = d.get("label", "Unknown")
            clue = _build_clue(d)
            clue_str = f" ({clue})" if clue else ""
            print(f"  [{i}] {label}{clue_str} — online")

        print()
        try:
            choice = input("  Which device to name? (number, q=quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice.lower() == "q":
            break

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(unnamed):
                print("  Invalid number.\n")
                continue
        except ValueError:
            print("  Enter a number.\n")
            continue

        device = unnamed[idx]
        device_ip = device["ip"]
        mac = device.get("mac", "unknown")
        label = device.get("label", "Device")

        # Auto-detect: countdown while pinging
        print(f"\n  Disconnect Wi-Fi on that device NOW")
        print(f"  {'-' * 40}")

        went_offline = False
        for remaining in range(20, 0, -1):
            print(f"  Waiting... {remaining:2d}s  ", end="\r")
            if _is_device_offline(device_ip):
                went_offline = True
                break
            time.sleep(1)

        print(" " * 40, end="\r")  # clear countdown line

        if went_offline:
            print(f"  Detected: {device_ip} went offline ✓")
        else:
            print(f"  Device didn't go offline.")
            try:
                retry = input("  Try again? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if retry == "y":
                print()
                continue
            else:
                print()
                continue

        # Show clues and ask for name
        clue = _build_clue(device)
        detail = f" ({clue})" if clue else ""
        print(f"\n  Device{detail}")
        try:
            name = input("  What do you call this device? ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not name:
            print("  Name cannot be empty.\n")
            continue

        set_known_name(mac, name)
        print(f"  Saved '{name}' ✓\n")

        # Remove from list and continue
        unnamed.pop(idx)
        if not unnamed:
            print("  All devices named!\n")
            break

        assign_stable_aliases(unnamed)

    print("  Returning to live scan...\n")


def main():
    import uvicorn
    import webbrowser

    host = "127.0.0.1"
    port = 8080
    url = f"http://{host}:{port}"

    print(f"\n  OpenCircuit starting at {url}")
    print(f"  Opening browser...\n")

    # Open browser after a short delay
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run("server:app", host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
