import {Database} from 'bun:sqlite';

export class Scanner{
  private db: Database;
  private insertScanStmt;
  private cleanOldScansStmt;
  private upsertDeviceStmt;
  private getDevicesStmt;
  private getScansStmt;

  constructor(path: string){
    this.db = new Database(path);
    this.db.run("PRAGMA journal_mode = WAL");
    this.createTables();
    this.insertScanStmt = this.db.prepare(`INSERT INTO scans (device_id, scanned_at, summary) VALUES (?, ?, ?)`);
    this.cleanOldScansStmt = this.db.prepare(`DELETE FROM scans WHERE device_id = ? AND scanned_at < datetime('now', '-30 days')`);
    this.upsertDeviceStmt = this.db.prepare(`
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
    this.getDevicesStmt = this.db.prepare(`SELECT * FROM devices WHERE device_id = ?`);
    this.getScansStmt = this.db.prepare(`SELECT * FROM scans WHERE device_id = ? ORDER BY scanned_at DESC`); 
  }

  private createTables() {
    this.db.run(`
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

    this.db.run(`
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        summary TEXT NOT NULL
      )
    `);
  }

  insertScan(deviceId: string, hosts: any[]) {
    this.insertScanStmt.run(deviceId, new Date().toISOString(), JSON.stringify(hosts));
  }
  
  insertOldScan(deviceId: string, hosts: any[], daysAgo: number) {
    const oldTimestamp = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString();
    this.insertScanStmt.run(deviceId, oldTimestamp, JSON.stringify(hosts));
  }

  cleanOldScans(deviceId: string) {
    this.cleanOldScansStmt.run(deviceId);
  }

  upsertDevices(deviceId: string, hosts: any[]) {
    const timestamp = new Date().toISOString();
    for (const host of hosts) {
      this.upsertDeviceStmt.run(
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

  getDevices(deviceId: string) {
    return this.getDevicesStmt.all(deviceId);
  }

  getScans(deviceId: string) {
    return this.getScansStmt.all(deviceId);
  }

}
