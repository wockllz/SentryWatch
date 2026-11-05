"use strict";
/**
 * SentryWatch end-to-end self test.
 * Boots real HTTP targets (healthy / bare / failing / slow) plus a webhook
 * receiver, then exercises checks, grading, incidents, alerts and the scheduler.
 */
const http = require("http");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const net = require("net");

const ROOT = path.join(__dirname, "..");
let failures = 0;

function ok(label, condition, detail) {
  if (condition) console.log("  ✓ " + label + (detail ? ` — ${detail}` : ""));
  else { failures += 1; console.log("  ✗ " + label + (detail ? ` — ${detail}` : "")); }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, timeoutMs, label) {
  const start = Date.now();
  for (;;) {
    try {
      const v = await fn();
      if (v) return v;
    } catch { /* retry */ }
    if (Date.now() - start > timeoutMs) throw new Error("timeout waiting for " + label);
    await sleep(200);
  }
}

const FULL_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin"
};

async function main() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "sw-test-"));
  const appPort = await freePort();

  // --- target servers
  let brokenMode = 500;
  const servers = [];

  const healthy = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", ...FULL_HEADERS });
    res.end("healthy site");
  });
  const bare = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", "x-powered-by": "Express" });
    res.end("bare site");
  });
  const broken = http.createServer((req, res) => {
    if (req.url.startsWith("/__mode")) {
      brokenMode = Number(new URL(req.url, "http://x").searchParams.get("code") || 500);
      res.writeHead(200);
      return res.end("ok");
    }
    res.writeHead(brokenMode, { "Content-Type": "text/plain", ...FULL_HEADERS });
    res.end("status " + brokenMode);
  });
  const webhookInbox = [];
  const webhook = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      try { webhookInbox.push(JSON.parse(raw)); } catch { /* ignore */ }
      res.writeHead(200);
      res.end("ok");
    });
  });

  for (const s of [healthy, bare, broken, webhook]) {
    await new Promise((r) => s.listen(0, "127.0.0.1", r));
    servers.push(s);
  }

  const urlHealthy = `http://127.0.0.1:${healthy.address().port}/`;
  const urlBare = `http://127.0.0.1:${bare.address().port}/`;
  const urlBroken = `http://127.0.0.1:${broken.address().port}/`;
  const urlWebhook = `http://127.0.0.1:${webhook.address().port}/alert`;
  const deadPort = await freePort();
  const urlDead = `http://127.0.0.1:${deadPort}/`;

  const app = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    env: {
      ...process.env,
      PORT: String(appPort),
      SW_DATA_DIR: dataDir,
      SW_TICK_MS: "400",
      SW_TIMEOUT_MS: "4000"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  const base = `http://127.0.0.1:${appPort}`;
  const post = (url, body) =>
    fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  let exitCode = 1;
  try {
    console.log("\n== SentryWatch self test ==\n[boot] app + 4 test servers");

    await waitFor(async () => (await fetch(`${base}/api/health`)).ok, 20000, "server");
    ok("server boots + health check", true);

    // ---------------------------------------------------- healthy check
    const healthyTarget = await (await post(`${base}/api/targets`, {
      name: "Healthy Site", url: urlHealthy, intervalSeconds: 3600
    })).json();
    ok("target created", !!healthyTarget.target.id && healthyTarget.target.status === "pending");

    const check1 = await (await post(`${base}/api/targets/${healthyTarget.target.id}/check`, {})).json();
    ok("healthy check is up", check1.check.ok === 1, `status ${check1.check.status_code}`);
    ok("response time measured", typeof check1.check.response_ms === "number" && check1.check.response_ms >= 0, `${check1.check.response_ms}ms`);
    ok("security grade A with full headers", check1.check.grade === "A", check1.check.grade);
    ok("no incident for healthy target", !check1.incidentOpened);

    // ---------------------------------------------------- bare headers
    const bareTarget = await (await post(`${base}/api/targets`, {
      name: "Bare Site", url: urlBare, intervalSeconds: 3600
    })).json();
    const check2 = await (await post(`${base}/api/targets/${bareTarget.target.id}/check`, {})).json();
    ok("bare site is up", check2.check.ok === 1);
    ok("missing headers lower the grade", ["C", "D", "F"].includes(check2.check.grade), check2.check.grade);
    const missingCsp = check2.check.findings.find((f) => !f.ok && /CSP/.test(f.header));
    ok("CSP finding reported", !!missingCsp);
    const poweredBy = check2.check.findings.find((f) => !f.ok && /X-Powered-By/.test(f.header));
    ok("stack leak flagged", !!poweredBy);

    // ---------------------------------------------------- incident lifecycle
    const brokenTarget = await (await post(`${base}/api/targets`, {
      name: "Broken API", url: urlBroken, intervalSeconds: 3600
    })).json();

    const down1 = await (await post(`${base}/api/targets/${brokenTarget.target.id}/check`, {})).json();
    ok("500 detected as down", down1.check.ok === 0 && down1.check.status_code === 500);
    ok("incident opened", down1.incidentOpened === true);

    const down2 = await (await post(`${base}/api/targets/${brokenTarget.target.id}/check`, {})).json();
    ok("second failure does not duplicate the incident", !down2.incidentOpened);

    const incidents1 = await (await fetch(`${base}/api/incidents`)).json();
    const openForBroken = incidents1.incidents.filter((i) => i.target_id === brokenTarget.target.id && !i.resolved_at);
    ok("exactly one open incident", openForBroken.length === 1, `${openForBroken.length} open`);

    // recover the server
    await fetch(`${urlBroken}__mode?code=200`);
    const up1 = await (await post(`${base}/api/targets/${brokenTarget.target.id}/check`, {})).json();
    ok("recovery detected", up1.check.ok === 1);
    ok("incident auto-resolved", up1.incidentResolved === true);

    const incidents2 = await (await fetch(`${base}/api/incidents`)).json();
    const resolved = incidents2.incidents.find((i) => i.target_id === brokenTarget.target.id);
    ok("incident marked resolved in the log", !!resolved.resolved_at);

    // ---------------------------------------------------- uptime math
    const brokenSummary = (await (await fetch(`${base}/api/overview`)).json()).targets.find((t) => t.id === brokenTarget.target.id);
    ok("uptime % computed from checks", brokenSummary.uptime24 === 33.3, `${brokenSummary.uptime24}% (1 of 3 checks up)`);

    // ---------------------------------------------------- webhook alerting
    const alertTarget = await (await post(`${base}/api/targets`, {
      name: "Dead Service", url: urlDead, intervalSeconds: 3600, webhook: urlWebhook
    })).json();
    await post(`${base}/api/targets/${alertTarget.target.id}/check`, {});
    await waitFor(() => webhookInbox.length > 0, 5000, "webhook delivery");
    const alert = webhookInbox[0];
    ok("webhook fired on down", alert.event === "down" && alert.target.name === "Dead Service", alert.event);
    ok("webhook carries the error", typeof alert.error === "string" && alert.error.length > 0, alert.error);

    // ---------------------------------------------------- scheduler
    const schedTarget = await (await post(`${base}/api/targets`, {
      name: "Scheduled", url: urlHealthy, intervalSeconds: 5
    })).json();
    await sleep(7000);
    const schedChecks = await (await fetch(`${base}/api/targets/${schedTarget.target.id}/checks`)).json();
    ok("scheduler runs checks automatically", schedChecks.checks.length >= 2, `${schedChecks.checks.length} automatic checks`);

    // ---------------------------------------------------- validation + delete
    const badUrl = await post(`${base}/api/targets`, { name: "x", url: "not-a-url" });
    ok("invalid URL rejected", badUrl.status === 400);

    const noName = await post(`${base}/api/targets`, { name: "", url: urlHealthy });
    ok("missing name rejected", noName.status === 400);

    const missing = await fetch(`${base}/api/targets/does-not-exist`);
    ok("unknown target gives 404", missing.status === 404);

    const delRes = await fetch(`${base}/api/targets/${schedTarget.target.id}`, { method: "DELETE" });
    ok("target deleted", delRes.status === 200);

    const afterDelete = await (await fetch(`${base}/api/targets/${schedTarget.target.id}/checks`)).json();
    ok("checks removed with the target", Array.isArray(afterDelete.checks) === false || afterDelete.checks.length === 0);

    const overview = await (await fetch(`${base}/api/overview`)).json();
    ok("overview totals correct", overview.totals.monitors === 4, `${overview.totals.monitors} monitors remain`);

    console.log("");
    if (failures === 0) {
      exitCode = 0;
      console.log("== selftest PASSED — SentryWatch is fully operational ◎ ==");
    } else {
      console.log(`== selftest FAILED — ${failures} assertion(s) failed ==`);
      exitCode = 1;
    }
  } catch (err) {
    console.log("\n== selftest FAILED (crash) ==\n" + err.message);
    exitCode = 1;
  } finally {
    try { app.kill(); } catch { /* ignore */ }
    for (const s of servers) { try { s.close(); } catch { /* ignore */ } }
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* ignore */ }
    try { process.exit(exitCode); } catch { /* ignore */ }
  }
}

main();
