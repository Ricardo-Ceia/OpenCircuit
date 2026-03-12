import { expect, test, describe, beforeEach } from "bun:test";
import { Scanner } from "../database.ts";

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
});

describe("insertScan", () => {
  test("inserts one row into scans", () => {
    scanner.insertScan("home-001", fakeHosts);
    const rows = scanner.getScans("home-001");
    expect(rows.length).toBe(1);
  });

  test("stores correct device_id", () => {
    scanner.insertScan("home-001", fakeHosts);
    const row = scanner.getScans("home-001")[0] as any;
    expect(row.device_id).toBe("home-001");
  });

  test("stores hosts as valid JSON", () => {
    scanner.insertScan("home-001", fakeHosts);
    const row = scanner.getScans("home-001")[0] as any;
    const parsed = JSON.parse(row.summary);
    expect(parsed.length).toBe(2);
    expect(parsed[0].ip).toBe("192.168.1.1");
  });

  test("stores a valid timestamp", () => {
    scanner.insertScan("home-001", fakeHosts);
    const row = scanner.getScans("home-001")[0] as any;
    const date = new Date(row.scanned_at);
    expect(date.toString()).not.toBe("Invalid Date");
  });

  test("multiple scans create multiple rows", () => {
    scanner.insertScan("home-001", fakeHosts);
    scanner.insertScan("home-001", fakeHosts);
    const rows = scanner.getScans("home-001");
    expect(rows.length).toBe(2);
  });

  test("scans from different modules are stored separately", () => {
    scanner.insertScan("home-001", fakeHosts);
    scanner.insertScan("home-002", fakeHosts);
    const rowsHome1 = scanner.getScans("home-001");
    const rowsHome2 = scanner.getScans("home-002");
    expect(rowsHome1.length).toBe(1);
    expect(rowsHome2.length).toBe(1);
  });
});

describe("upsertDevices", () => {
  test("inserts one row per host", () => {
    scanner.upsertDevices("home-001", fakeHosts);
    const rows = scanner.getDevices("home-001");
    expect(rows.length).toBe(2);
  });

  test("does not duplicate on second upsert", () => {
    scanner.upsertDevices("home-001", fakeHosts);
    scanner.upsertDevices("home-001", fakeHosts);
    const rows = scanner.getDevices("home-001");
    expect(rows.length).toBe(2);
  });

  test("updates existing row on conflict", () => {
    scanner.upsertDevices("home-001", fakeHosts);
    const updated = [{ ...fakeHosts[0], status: "down", hostname: "updated-router" }];
    scanner.upsertDevices("home-001", updated);
    const rows = scanner.getDevices("home-001") as any[];
    const row = rows.find(r => r.ip === "192.168.1.1");
    expect(row.status).toBe("down");
    expect(row.hostname).toBe("updated-router");
  });

  test("stores correct device_id per host", () => {
    scanner.upsertDevices("home-001", fakeHosts);
    const rows = scanner.getDevices("home-001") as any[];
    expect(rows.every(r => r.device_id === "home-001")).toBe(true);
  });

  test("same ip from different modules creates separate rows", () => {
    scanner.upsertDevices("home-001", fakeHosts);
    scanner.upsertDevices("home-002", fakeHosts);
    const rowsHome1 = scanner.getDevices("home-001");
    const rowsHome2 = scanner.getDevices("home-002");
    expect(rowsHome1.length).toBe(2);
    expect(rowsHome2.length).toBe(2);
  });

  test("stores null for missing optional fields", () => {
    scanner.upsertDevices("home-001", fakeHosts);
    const rows = scanner.getDevices("home-001") as any[];
    const row = rows.find(r => r.ip === "192.168.1.2");
    expect(row.hostname).toBeNull();
    expect(row.open_ports).toBeNull();
  });
});

describe("cleanOldScans", () => {
  test("does not delete recent scans", () => {
    scanner.insertScan("home-001", fakeHosts);
    scanner.cleanOldScans("home-001");
    const rows = scanner.getScans("home-001");
    expect(rows.length).toBe(1);
  });

  test("deletes scans older than 30 days", () => {
    scanner.insertOldScan("home-001", fakeHosts, 31);
    scanner.cleanOldScans("home-001");
    const rows = scanner.getScans("home-001");
    expect(rows.length).toBe(0);
  });

  test("only deletes scans for the given device_id", () => {
    scanner.insertOldScan("home-001", fakeHosts, 31);
    scanner.insertScan("home-002", fakeHosts);
    scanner.cleanOldScans("home-001");
    const rows = scanner.getScans("home-002");
    expect(rows.length).toBe(1);
  });

  test("keeps recent scans when old ones are deleted", () => {
    scanner.insertOldScan("home-001", fakeHosts, 31);
    scanner.insertScan("home-001", fakeHosts);
    scanner.cleanOldScans("home-001");
    const rows = scanner.getScans("home-001");
    expect(rows.length).toBe(1);
  });
});
