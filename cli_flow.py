from __future__ import annotations

from collections.abc import Callable
import sys
import time
from typing import Any

from device_history import (
    _get_retention_hours,
    format_last_seen,
    get_history_as_list,
    get_history_stats,
)
from identity import assign_stable_aliases
from known_devices import set_known_name
from scan_pipeline import ping_ip, run_single_scan


def build_clue(device: dict[str, Any]) -> str:
    """Build a compact device clue from fingerprint and vendor fields."""
    clues: list[str] = []
    fingerprint = device.get("fingerprint", {})
    vendor = device.get("vendor")

    manufacturer = fingerprint.get("manufacturer") if isinstance(fingerprint, dict) else None
    model = fingerprint.get("model") if isinstance(fingerprint, dict) else None

    if manufacturer and model:
        clues.append(f"{manufacturer} {model}")
    elif manufacturer:
        clues.append(str(manufacturer))
    elif vendor:
        clues.append(str(vendor))

    return " · ".join(clues)


def print_display(history: dict[str, dict[str, Any]], scan_count: int):
    """Print a console table for current device history."""
    devices = get_history_as_list(history)
    stats = get_history_stats(history)
    retention = _get_retention_hours()

    devices = assign_stable_aliases(devices)

    identity_order = {"claimed": 0, "verified": 1, "identified": 2, "unidentified": 3}
    status_order = {"online": 0, "offline": 1}
    devices.sort(
        key=lambda device: (
            identity_order.get(device.get("identity_status", "unidentified"), 9),
            status_order.get(device.get("status", "offline"), 9),
            device.get("first_seen", ""),
        )
    )

    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    print("=" * 140)
    print(f"  NETWORK SCANNER - Scan #{scan_count} | Retention: {retention}h | Press Ctrl+C to exit")
    print("=" * 140)
    print(f"\n{'Label':<30} {'Clue':<28} {'Identity':<12} {'Status':<10} {'Last Seen':<12} {'IP':<18} {'Scans'}")
    print("-" * 140)

    for device in devices:
        label = device.get("label", device.get("hostname", "Unidentified device"))
        identity = device.get("identity_status", "unidentified")
        status = "ONLINE" if device.get("status") == "online" else "OFFLINE"
        last_seen = format_last_seen(device.get("last_seen", ""))
        sources = device.get("sources", device.get("source", []))
        if isinstance(sources, str):
            sources = sources.split("+") if sources else []
        clue = build_clue(device)

        print(f"{label:<30} {clue:<28} {identity:<12} {status:<10} {last_seen:<12} {device['ip']:<18} {'+'.join(sources)}")

    print("-" * 140)
    print(
        f"  Total: {stats['total']} | Online: {stats['online']} | Offline: {stats['offline']} | "
        f"Verified: {stats['verified']} | Unidentified: {stats['unidentified']}"
    )

    unnamed_count = sum(
        1
        for device in devices
        if device.get("identity_status") == "unidentified" and device.get("status") == "online"
    )
    if unnamed_count > 0:
        print(f"  {unnamed_count} unnamed device(s) — type 'i' + Enter to name them")

    print()


def is_device_offline(
    ip: str,
    retries: int = 2,
    *,
    ping_fn: Callable[[str], bool] = ping_ip,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> bool:
    """Return True when a device appears offline after retry checks."""
    for _ in range(retries):
        if ping_fn(ip):
            return False
        sleep_fn(0.3)
    return True


def run_identify_flow(subnet: str):
    """Interactive naming flow for online unidentified devices."""
    print("\n  Scanning network...\n")
    scan_results = run_single_scan(subnet, mdns_timeout=5)

    unnamed = []
    for device in scan_results:
        if device.get("identity_status") in ("claimed",):
            continue
        if device.get("label_source") == "known":
            continue
        if device.get("status") != "online":
            continue
        mac = device.get("mac", "unknown")
        if mac == "unknown":
            continue
        unnamed.append(device)

    if not unnamed:
        print("  No online unnamed devices found.\n")
        return

    assign_stable_aliases(unnamed)

    while unnamed:
        print("  Unnamed devices")
        print(f"  {'-' * 40}")
        for idx, device in enumerate(unnamed, 1):
            label = device.get("label", "Unknown")
            clue = build_clue(device)
            clue_str = f" ({clue})" if clue else ""
            print(f"  [{idx}] {label}{clue_str} — online")

        print()
        try:
            choice = input("  Which device to name? (number, q=quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice.lower() == "q":
            break

        try:
            index = int(choice) - 1
            if index < 0 or index >= len(unnamed):
                print("  Invalid number.\n")
                continue
        except ValueError:
            print("  Enter a number.\n")
            continue

        device = unnamed[index]
        device_ip = device["ip"]
        mac = device.get("mac", "unknown")

        print("\n  Disconnect Wi-Fi on that device NOW")
        print(f"  {'-' * 40}")

        went_offline = False
        for remaining in range(20, 0, -1):
            print(f"  Waiting... {remaining:2d}s  ", end="\r")
            if is_device_offline(device_ip):
                went_offline = True
                break
            time.sleep(1)

        print(" " * 40, end="\r")

        if went_offline:
            print(f"  Detected: {device_ip} went offline ✓")
        else:
            print("  Device didn't go offline.")
            try:
                retry = input("  Try again? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if retry == "y":
                print()
                continue
            print()
            continue

        clue = build_clue(device)
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

        unnamed.pop(index)
        if not unnamed:
            print("  All devices named!\n")
            break

        assign_stable_aliases(unnamed)

    print("  Returning to live scan...\n")
