import { expect, test, describe, beforeEach } from "bun:test";
import { initDatabase, insertScan, upsertDevices, cleanOldScans } from "../database.ts";
import type { Database } from "bun:sqlite";

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

let db: Database;

beforeEach(() => {
  db = initDatabase(":memory:");
});

describe("insertScan", () => {
  test("inserts one row into scans", () => {
    insertScan(db, "home-001", fakeHosts);
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(1);
  });

  test("stores correct device_id", () => {
    insertScan(db, "home-001", fakeHosts);
    const row = db.query("SELECT * FROM scans").get() as any;
    expect(row.device_id).toBe("home-001");
  });

  test("stores hosts as valid JSON", () => {
    insertScan(db, "home-001", fakeHosts);
    const row = db.query("SELECT * FROM scans").get() as any;
    const parsed = JSON.parse(row.summary);
    expect(parsed.length).toBe(2);
    expect(parsed[0].ip).toBe("192.168.1.1");
  });

  test("stores a valid timestamp", () => {
    insertScan(db, "home-001", fakeHosts);
    const row = db.query("SELECT * FROM scans").get() as any;
    const date = new Date(row.scanned_at);
    expect(date.toString()).not.toBe("Invalid Date");
  });

  test("multiple scans create multiple rows", () => {
    insertScan(db, "home-001", fakeHosts);
    insertScan(db, "home-001", fakeHosts);
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(2);
  });

  test("scans from different modules are stored separately", () => {
    insertScan(db, "home-001", fakeHosts);
    insertScan(db, "home-002", fakeHosts);
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(2);
  });
});

describe("upsertDevices", () => {
  test("inserts one row per host", () => {
    upsertDevices(db, "home-001", fakeHosts);
    const rows = db.query("SELECT * FROM devices").all();
    expect(rows.length).toBe(2);
  });

  test("does not duplicate on second upsert", () => {
    upsertDevices(db, "home-001", fakeHosts);
    upsertDevices(db, "home-001", fakeHosts);
    const rows = db.query("SELECT * FROM devices").all();
    expect(rows.length).toBe(2);
  });

  test("updates existing row on conflict", () => {
    upsertDevices(db, "home-001", fakeHosts);
    const updated = [{ ...fakeHosts[0], status: "down", hostname: "updated-router" }];
    upsertDevices(db, "home-001", updated);
    const row = db.query("SELECT * FROM devices WHERE ip = '192.168.1.1'").get() as any;
    expect(row.status).toBe("down");
    expect(row.hostname).toBe("updated-router");
  });

  test("stores correct device_id per host", () => {
    upsertDevices(db, "home-001", fakeHosts);
    const rows = db.query("SELECT * FROM devices").all() as any[];
    expect(rows.every(r => r.device_id === "home-001")).toBe(true);
  });

  test("same ip from different modules creates separate rows", () => {
    upsertDevices(db, "home-001", fakeHosts);
    upsertDevices(db, "home-002", fakeHosts);
    const rows = db.query("SELECT * FROM devices").all();
    expect(rows.length).toBe(4);
  });

  test("stores null for missing optional fields", () => {
    upsertDevices(db, "home-001", fakeHosts);
    const row = db.query("SELECT * FROM devices WHERE ip = '192.168.1.2'").get() as any;
    expect(row.hostname).toBeNull();
    expect(row.open_ports).toBeNull();
  });
});

describe("cleanOldScans", () => {
  test("does not delete recent scans", () => {
    insertScan(db, "home-001", fakeHosts);
    cleanOldScans(db, "home-001");
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(1);
  });

  test("deletes scans older than 30 days", () => {
    const oldTimestamp = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    db.run("INSERT INTO scans (device_id, scanned_at, summary) VALUES (?, ?, ?)", [
      "home-001",
      oldTimestamp,
      JSON.stringify(fakeHosts),
    ]);
    cleanOldScans(db, "home-001");
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(0);
  });

  test("only deletes scans for the given device_id", () => {
    const oldTimestamp = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    db.run("INSERT INTO scans (device_id, scanned_at, summary) VALUES (?, ?, ?)", [
      "home-001",
      oldTimestamp,
      JSON.stringify(fakeHosts),
    ]);
    insertScan(db, "home-002", fakeHosts);
    cleanOldScans(db, "home-001");
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(1);
    const remaining = rows[0] as any;
    expect(remaining.device_id).toBe("home-002");
  });

  test("keeps recent scans when old ones are deleted", () => {
    const oldTimestamp = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    db.run("INSERT INTO scans (device_id, scanned_at, summary) VALUES (?, ?, ?)", [
      "home-001",
      oldTimestamp,
      JSON.stringify(fakeHosts),
    ]);
    insertScan(db, "home-001", fakeHosts);
    cleanOldScans(db, "home-001");
    const rows = db.query("SELECT * FROM scans").all();
    expect(rows.length).toBe(1);
  });
});
