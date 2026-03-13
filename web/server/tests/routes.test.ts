import { expect, test, describe, beforeEach } from "bun:test";
import { Scanner } from "../database.ts";
import { getDevicesHandler, getScansHandler } from "../routes.ts";

let scanner: Scanner;

const fakeHosts = [
  {
    ip: "192.168.1.1",
    status: "up",
    presence: "online",
    connectivity_source: "active_probe",
    hostname: "router",
    hostname_source: "reverse_dns",
    hostname_confidence: 90,
    mac: null,
    open_ports: "53,80",
  },
  {
    ip: "192.168.1.2",
    status: "down",
    presence: "offline",
    connectivity_source: "none",
    hostname: null,
    hostname_source: null,
    hostname_confidence: 0,
    mac: null,
    open_ports: null,
  },
];

beforeEach(() => {
  scanner = new Scanner(":memory:");
  scanner.upsertDevices("home-001", fakeHosts);
  scanner.insertScan("home-001", fakeHosts);
});

describe("getDevicesHandler", () => {
  test("returns 200", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    expect(res.status).toBe(200);
  });

  test("returns correct content-type", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });

  test("returns an array", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("returns correct number of devices", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.length).toBe(2);
  });

  test("returns devices with correct fields", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    const data = await res.json() as any[];
    const device = data[0];
    expect(device).toHaveProperty("ip");
    expect(device).toHaveProperty("status");
    expect(device).toHaveProperty("hostname");
    expect(device).toHaveProperty("device_id");
    expect(device).toHaveProperty("last_seen_at");
  });

  test("returns devices with correct device_id", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.every((d: any) => d.device_id === "home-001")).toBe(true);
  });

  test("returns correct ip addresses", async () => {
    const res = getDevicesHandler(scanner, "home-001");
    const data = await res.json() as any[];
    const ips = data.map((d: any) => d.ip);
    expect(ips).toContain("192.168.1.1");
    expect(ips).toContain("192.168.1.2");
  });

  test("returns empty array for unknown deviceId", async () => {
    const res = getDevicesHandler(scanner, "unknown-device");
    const data = await res.json() as any[];
    expect(data.length).toBe(0);
  });

  test("does not mix devices from different modules", async () => {
    scanner.upsertDevices("home-002", fakeHosts);
    const res = getDevicesHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.every((d: any) => d.device_id === "home-001")).toBe(true);
  });
});

describe("getScansHandler", () => {
  test("returns 200", async () => {
    const res = getScansHandler(scanner, "home-001");
    expect(res.status).toBe(200);
  });

  test("returns correct content-type", async () => {
    const res = getScansHandler(scanner, "home-001");
    expect(res.headers.get("Content-Type")).toBe("application/json");
  });

  test("returns an array", async () => {
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("returns correct number of scans", async () => {
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.length).toBe(1);
  });

  test("returns scans with correct fields", async () => {
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    const scan = data[0];
    expect(scan).toHaveProperty("id");
    expect(scan).toHaveProperty("device_id");
    expect(scan).toHaveProperty("scanned_at");
    expect(scan).toHaveProperty("summary");
  });

  test("summary is a parsed array not a string", async () => {
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(Array.isArray(data[0].summary)).toBe(true);
  });

  test("summary contains correct hosts", async () => {
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    const summary = data[0].summary;
    expect(summary.length).toBe(2);
    expect(summary[0].ip).toBe("192.168.1.1");
    expect(summary[1].ip).toBe("192.168.1.2");
  });

  test("returns scans with correct device_id", async () => {
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.every((s: any) => s.device_id === "home-001")).toBe(true);
  });

  test("returns empty array for unknown deviceId", async () => {
    const res = getScansHandler(scanner, "unknown-device");
    const data = await res.json() as any[];
    expect(data.length).toBe(0);
  });

  test("returns scans newest first", async () => {
    scanner.insertScan("home-001", fakeHosts);
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.length).toBe(2);
    const first = new Date(data[0].scanned_at).getTime();
    const second = new Date(data[1].scanned_at).getTime();
    expect(first).toBeGreaterThanOrEqual(second);
  });

  test("does not mix scans from different modules", async () => {
    scanner.insertScan("home-002", fakeHosts);
    const res = getScansHandler(scanner, "home-001");
    const data = await res.json() as any[];
    expect(data.every((s: any) => s.device_id === "home-001")).toBe(true);
  });
});
