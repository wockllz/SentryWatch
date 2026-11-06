"use strict";
/**
 * SentryWatch checker.
 *
 * One check = one HTTP request with a hard timeout, plus:
 *  - response time measurement
 *  - status/expected-status evaluation
 *  - security header analysis with a letter grade
 *  - TLS certificate expiry for https targets
 *  - incident open/resolve transitions
 *  - webhook alert on the down transition
 */
const tls = require("tls");
const { URL } = require("url");
const db = require("./db");

const TIMEOUT_MS = Number(process.env.SW_TIMEOUT_MS || 15000);

const SECURITY_HEADERS = [
  { key: "strict-transport-security", label: "HSTS", weight: 15, httpsOnly: true, hint: "Add Strict-Transport-Security to force HTTPS." },
  { key: "content-security-policy", label: "CSP", weight: 20, hint: "Add a Content-Security-Policy to limit script sources." },
  { key: "x-frame-options", label: "X-Frame-Options", weight: 10, hint: "Add X-Frame-Options: DENY to stop clickjacking." },
  { key: "x-content-type-options", label: "X-Content-Type-Options", weight: 10, hint: "Add X-Content-Type-Options: nosniff." },
  { key: "referrer-policy", label: "Referrer-Policy", weight: 10, hint: "Add Referrer-Policy: strict-origin-when-cross-origin." }
];

function gradeFor(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

function analyzeHeaders(headersObj, isHttps) {
  const findings = [];
  let score = 100;

  for (const h of SECURITY_HEADERS) {
    const present = !!headersObj[h.key];
    if (present) {
      findings.push({ header: h.label, ok: true, message: `${h.label} present.` });
    } else if (!(h.httpsOnly && !isHttps)) {
      score -= h.weight;
      findings.push({ header: h.label, ok: false, message: `${h.label} missing. ${h.hint}` });
    }
  }

  // extras worth flagging
  const server = headersObj["server"];
  if (server) findings.push({ header: "Server", ok: true, message: `Server header exposes: ${server}`, info: true });

  const powered = headersObj["x-powered-by"];
  if (powered) {
    score -= 5;
    findings.push({ header: "X-Powered-By", ok: false, message: `X-Powered-By leaks the stack (${powered}). Remove it.` });
  }

  const clamped = Math.max(0, score);
  return { score: clamped, grade: gradeFor(clamped), findings };
}

function tlsExpiryDays(hostname, port = 443) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };

    try {
      const socket = tls.connect(
        { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 6000 },
        () => {
          try {
            const cert = socket.getPeerCertificate();
            if (cert && cert.valid_to) {
              const days = Math.ceil((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
              finish(days);
            } else finish(null);
          } catch {
            finish(null);
          } finally {
            socket.end();
          }
        }
      );
      socket.on("error", () => finish(null));
      socket.on("timeout", () => { socket.destroy(); finish(null); });
    } catch {
      finish(null);
    }
  });
}

async function performCheck(targetId) {
  const target = db.getTarget(targetId);
  if (!target) throw new Error("Target not found");

  const started = Date.now();
  const result = {
    ok: false,
    statusCode: null,
    responseMs: null,
    error: null,
    tlsDays: null,
    grade: null,
    findings: [],
    ts: started
  };

  let parsed = null;
  try {
    parsed = new URL(target.url);
  } catch {
    result.error = "Invalid URL";
  }

  if (parsed) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(target.url, {
        redirect: "follow",
        signal: controller.signal,
        headers: { "User-Agent": "SentryWatch/1.0 (+https://github.com/wockllz/SentryWatch)" }
      });
      result.responseMs = Date.now() - started;
      result.statusCode = res.status;
      result.ok = res.status === Number(target.expected_status || 200);

      if (!result.ok) result.error = `Expected ${target.expected_status}, got ${res.status}`;

      const headers = {};
      res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
      const security = analyzeHeaders(headers, parsed.protocol === "https:");
      result.grade = security.grade;
      result.findings = security.findings;

      if (parsed.protocol === "https:") {
        result.tlsDays = await tlsExpiryDays(parsed.hostname, parsed.port ? Number(parsed.port) : 443);
        if (result.tlsDays !== null && result.tlsDays <= 0) {
          result.ok = false;
          result.error = "TLS certificate expired";
        } else if (result.tlsDays !== null && result.tlsDays < 14) {
          result.findings.push({ header: "TLS", ok: false, message: `Certificate expires in ${result.tlsDays} days.` });
        }
      }
    } catch (err) {
      result.responseMs = Date.now() - started;
      result.error = err.name === "AbortError" ? `Timed out after ${TIMEOUT_MS}ms` : err.message;
    } finally {
      clearTimeout(timer);
    }
  }

  const saved = db.addCheck(target.id, result);

  // incident transitions
  const open = db.openIncident(target.id);
  if (!result.ok && !open) {
    const incident = db.createIncident(target.id, result.error || "Check failed");
    notifyWebhook(target, result, incident, "down");
    saved.incidentOpened = true;
  } else if (result.ok && open) {
    const resolved = db.resolveIncident(open.id);
    notifyWebhook(target, result, resolved, "recovered");
    saved.incidentResolved = true;
  }

  return {
    check: { ...saved, findings: result.findings },
    target,
    incidentOpened: saved.incidentOpened === true,
    incidentResolved: saved.incidentResolved === true
  };
}

function notifyWebhook(target, result, incident, event) {
  if (!target.webhook) return;
  const payload = JSON.stringify({
    event,
    target: { id: target.id, name: target.name, url: target.url },
    status: result.statusCode,
    error: result.error,
    at: new Date().toISOString(),
    incidentId: incident.id
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  fetch(target.webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: payload,
    signal: controller.signal
  })
    .catch(() => { /* alerts are best-effort */ })
    .finally(() => clearTimeout(timer));
}

/* ------------------------------------------------------------- dashboard math */
function uptimePercent(targetId, sinceMs) {
  const checks = db.checksSince(targetId, sinceMs);
  if (!checks.length) return null;
  const okCount = checks.filter((c) => c.ok).length;
  return Number(((okCount / checks.length) * 100).toFixed(1));
}

function checksLastHour(targetId) {
  const since = Date.now() - 60 * 60 * 1000;
  return db.checksSince(targetId, since).length;
}

function summarize(target) {
  const day = 24 * 60 * 60 * 1000;
  const last = db.lastCheck(target.id);
  const uptime24 = uptimePercent(target.id, Date.now() - day);
  const incident = db.openIncident(target.id);
  const recent = db.recentChecks(target.id, 30);

  return {
    id: target.id,
    name: target.name,
    url: target.url,
    intervalSeconds: target.interval_seconds,
    expectedStatus: target.expected_status,
    webhook: target.webhook,
    active: !!target.active,
    status: last ? (last.ok ? "up" : "down") : "pending",
    lastCheck: last,
    uptime24,
    avgMs: db.avgResponse(target.id, Date.now() - day),
    incident: incident || null,
    security: last
      ? { grade: last.grade, findings: JSON.parse(last.findings || "[]"), tlsDays: last.tls_days }
      : null,
    checksLastHour: checksLastHour(target.id),
    nextCheckIn: last ? Math.max(0, Math.ceil((last.ts + Math.max(5, target.interval_seconds) * 1000 - Date.now()) / 1000)) : 0,
    sparkline: recent.map((c) => ({ ok: !!c.ok, ms: c.response_ms, ts: c.ts }))
  };
}

module.exports = {
  performCheck,
  summarize,
  checksLastHour,
  uptimePercent,
  analyzeHeaders,
  tlsExpiryDays,
  TIMEOUT_MS
};
