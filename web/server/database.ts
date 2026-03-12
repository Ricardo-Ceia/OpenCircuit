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

