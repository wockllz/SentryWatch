"use strict";
const path = require("path");
const express = require("express");
const { securityHeaders } = require("./middleware/security");
const db = require("./src/db");
const checker = require("./src/checker");
const scheduler = require("./src/scheduler");

const app = express();
const PORT = process.env.PORT || 4700;

app.set("view engine", "ejs");

app.use(securityHeaders);
app.set("views", path.join(__dirname, "views"));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => res.render("index"));
app.get("/api/health", (req, res) => res.json({ ok: true, name: "SentryWatch" }));

/* ---------------------------------------------------------------- targets */
app.get("/api/targets", (req, res) => {
  res.json({ targets: db.listTargets().map((t) => checker.summarize(t)) });
});

app.post("/api/targets", (req, res) => {
  const body = req.body || {};
  const name = String(body.name || "").trim();
  const url = String(body.url || "").trim();

  if (!name) return res.status(400).json({ error: "Target name required." });
  if (!/^https?:\/\/.+/i.test(url)) return res.status(400).json({ error: "URL must start with http:// or https://" });

  const interval = Math.max(5, Math.min(86400, Number(body.intervalSeconds) || 60));
  const expected = Math.max(100, Math.min(599, Number(body.expectedStatus) || 200));

  const target = db.createTarget({
    name: name.slice(0, 80),
    url: url.slice(0, 500),
    intervalSeconds: interval,
    expectedStatus: expected,
    webhook: String(body.webhook || "").slice(0, 500)
  });

  res.status(201).json({ target: checker.summarize(target) });
});

app.patch("/api/targets/:id", (req, res) => {
  const target = db.updateTarget(req.params.id, req.body || {});
  if (!target) return res.status(404).json({ error: "Target not found." });
  res.json({ target: checker.summarize(target) });
});

app.delete("/api/targets/:id", (req, res) => {
  if (!db.getTarget(req.params.id)) return res.status(404).json({ error: "Target not found." });
  db.deleteTarget(req.params.id);
  res.json({ ok: true });
});

app.post("/api/targets/:id/check", async (req, res) => {
  if (!db.getTarget(req.params.id)) return res.status(404).json({ error: "Target not found." });
  try {
    const result = await checker.performCheck(req.params.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/targets/:id/checks", (req, res) => {
  if (!db.getTarget(req.params.id)) return res.status(404).json({ error: "Target not found." });
  res.json({ checks: db.recentChecks(req.params.id, Number(req.query.limit) || 50) });
});

/* -------------------------------------------------------------- incidents */
app.get("/api/incidents", (req, res) => {
  res.json({ incidents: db.listIncidents(Number(req.query.limit) || 30) });
});

/* ---------------------------------------------------------------- overview */
app.get("/api/overview", (req, res) => {
  const targets = db.listTargets().map((t) => checker.summarize(t));
  const up = targets.filter((t) => t.status === "up").length;
  const down = targets.filter((t) => t.status === "down").length;
  const pending = targets.filter((t) => t.status === "pending").length;
  const avgMsList = targets.map((t) => t.avgMs).filter((v) => typeof v === "number");
  const avgMs = avgMsList.length ? Math.round(avgMsList.reduce((a, b) => a + b, 0) / avgMsList.length) : null;

  res.json({
    targets,
    totals: { monitors: targets.length, up, down, pending, avgMs },
    incidents: db.listIncidents(10)
  });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

const server = app.listen(PORT, () => {
  console.log(`\n◎ SentryWatch running on http://localhost:${PORT}`);
  if (process.env.SW_DISABLE_SCHEDULER !== "1") scheduler.start();
  else console.log("[scheduler] disabled by SW_DISABLE_SCHEDULER");
});

module.exports = server;
