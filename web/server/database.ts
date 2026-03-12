import {Database} from 'bun:sqlite';

export function initDatabase(path: string) {
  const db = new Database(path);
  db.run("PRAGMA journal_mode = WAL;");

  db.run(`
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      ip TEXT NOT NULL,
      status TEXT,
      presence TEXT,
      connectivity_source TEXT,
      hostname TEXT,
      hostname_source TEXT,
      hostname_confidence INTEGER,
      mac TEXT,
      open_ports TEXT,
      last_seen_at TEXT NOT NULL,
      UNIQUE(device_id, ip)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      scanned_at TEXT NOT NULL,
      summary TEXT NOT NULL
    )
  `);

  return db;
}


export function insertScan(db: Database, deviceId: string, hosts: any[]){
  const timestamp = new Date().toISOString();
  const stmt = db.prepare(`INSERT INTO scans (device_id, scanned_at, summary) VALUES (?, ?, ?)`);
  stmt.run(deviceId, timestamp, JSON.stringify(hosts));
}

export function cleanOldScans(db: Database, deviceId: string) {
  const stmt = db.prepare(`DELETE FROM scans WHERE device_id = ? AND scanned_at < datetime('now', '-30 days')`);
  stmt.run(deviceId);
}

export function upsertDevices(db: Database, deviceId: string, hosts: any[]) {
  const stmt = db.prepare(`
    INSERT INTO devices (device_id, ip, status, presence, connectivity_source, hostname, hostname_source, hostname_confidence, mac, open_ports, last_seen_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(device_id, ip) DO UPDATE SET
      status = excluded.status,
      presence = excluded.presence,
      connectivity_source = excluded.connectivity_source,
      hostname = excluded.hostname,
      hostname_source = excluded.hostname_source,
      hostname_confidence = excluded.hostname_confidence,
      mac = excluded.mac,
      open_ports = excluded.open_ports,
      last_seen_at = excluded.last_seen_at
  `);

  const timestamp = new Date().toISOString();
  for (const host of hosts) {
    stmt.run(
      deviceId,
      host.ip,
      host.status,
      host.presence ?? null,
      host.connectivity_source ?? null,
      host.hostname ?? null,
      host.hostname_source ?? null,
      host.hostname_confidence ?? 0,
      host.mac ?? null,
      host.open_ports ?? null,
      timestamp
    );
  }
}
