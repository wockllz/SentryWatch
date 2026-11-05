"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const DATA_DIR = process.env.SW_DATA_DIR || path.join(process.cwd(), "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "sentrywatch.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  interval_seconds INTEGER DEFAULT 60,
  expected_status INTEGER DEFAULT 200,
  webhook TEXT DEFAULT '',
  active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  status_code INTEGER,
  response_ms INTEGER,
  error TEXT,
  tls_days INTEGER,
  grade TEXT,
  findings TEXT,
  FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  resolved_at INTEGER,
  reason TEXT,
  FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target_id, ts);
`);

const uid = () => crypto.randomUUID();

/* ---------------------------------------------------------------- targets */
function createTarget({ name, url, intervalSeconds, expectedStatus, webhook }) {
  const id = uid();
  db.prepare(
    `INSERT INTO targets (id, name, url, interval_seconds, expected_status, webhook, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, name, url, intervalSeconds, expectedStatus, webhook, Date.now());
  return getTarget(id);
}

function getTarget(id) {
  return db.prepare("SELECT * FROM targets WHERE id = ?").get(id) || null;
}

function listTargets() {
  return db.prepare("SELECT * FROM targets ORDER BY created_at ASC").all();
}

function updateTarget(id, patch) {
  const t = getTarget(id);
  if (!t) return null;
  db.prepare(
    "UPDATE targets SET name = ?, url = ?, interval_seconds = ?, expected_status = ?, webhook = ?, active = ? WHERE id = ?"
  ).run(
    patch.name !== undefined ? patch.name : t.name,
    patch.url !== undefined ? patch.url : t.url,
    patch.intervalSeconds !== undefined ? patch.intervalSeconds : t.interval_seconds,
    patch.expectedStatus !== undefined ? patch.expectedStatus : t.expected_status,
    patch.webhook !== undefined ? patch.webhook : t.webhook,
    patch.active !== undefined ? (patch.active ? 1 : 0) : t.active,
    id
  );
  return getTarget(id);
}

function deleteTarget(id) {
  db.prepare("DELETE FROM checks WHERE target_id = ?").run(id);
  db.prepare("DELETE FROM incidents WHERE target_id = ?").run(id);
  db.prepare("DELETE FROM targets WHERE id = ?").run(id);
}

/* ----------------------------------------------------------------- checks */
function addCheck(targetId, result) {
  const id = uid();
  db.prepare(
    `INSERT INTO checks (id, target_id, ts, ok, status_code, response_ms, error, tls_days, grade, findings)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    targetId,
    result.ts || Date.now(),
    result.ok ? 1 : 0,
    result.statusCode ?? null,
    result.responseMs ?? null,
    result.error ?? null,
    result.tlsDays ?? null,
    result.grade ?? null,
    JSON.stringify(result.findings || [])
  );
  return db.prepare("SELECT * FROM checks WHERE id = ?").get(id);
}

function lastCheck(targetId) {
  return db.prepare("SELECT * FROM checks WHERE target_id = ? ORDER BY ts DESC LIMIT 1").get(targetId) || null;
}

function recentChecks(targetId, limit = 30) {
  return db
    .prepare("SELECT * FROM checks WHERE target_id = ? ORDER BY ts DESC LIMIT ?")
    .all(targetId, limit)
    .reverse()
    .map((c) => ({ ...c, findings: JSON.parse(c.findings || "[]") }));
}

function checksSince(targetId, sinceMs) {
  return db.prepare("SELECT * FROM checks WHERE target_id = ? AND ts >= ? ORDER BY ts ASC").all(targetId, sinceMs);
}

function avgResponse(targetId, sinceMs) {
  const row = db
    .prepare("SELECT AVG(response_ms) AS avg FROM checks WHERE target_id = ? AND ts >= ? AND response_ms IS NOT NULL")
    .get(targetId, sinceMs);
  return row && row.avg ? Math.round(row.avg) : null;
}

/* -------------------------------------------------------------- incidents */
function openIncident(targetId) {
  return db.prepare("SELECT * FROM incidents WHERE target_id = ? AND resolved_at IS NULL").get(targetId) || null;
}

function createIncident(targetId, reason) {
  const id = uid();
  db.prepare("INSERT INTO incidents (id, target_id, started_at, reason) VALUES (?, ?, ?, ?)").run(
    id, targetId, Date.now(), reason
  );
  return db.prepare("SELECT * FROM incidents WHERE id = ?").get(id);
}

function resolveIncident(id) {
  db.prepare("UPDATE incidents SET resolved_at = ? WHERE id = ?").run(Date.now(), id);
  return db.prepare("SELECT * FROM incidents WHERE id = ?").get(id);
}

function listIncidents(limit = 30) {
  return db
    .prepare(
      `SELECT i.*, t.name AS target_name
       FROM incidents i JOIN targets t ON t.id = i.target_id
       ORDER BY i.started_at DESC LIMIT ?`
    )
    .all(limit);
}

module.exports = {
  uid,
  createTarget,
  getTarget,
  listTargets,
  updateTarget,
  deleteTarget,
  addCheck,
  lastCheck,
  recentChecks,
  checksSince,
  avgResponse,
  openIncident,
  createIncident,
  resolveIncident,
  listIncidents
};
