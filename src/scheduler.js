"use strict";
/** Simple tick-based scheduler: every target runs on its own interval. */
const db = require("./db");
const checker = require("./checker");

const TICK_MS = Number(process.env.SW_TICK_MS || 5000);
let timer = null;
let running = false;

function dueTargets(now) {
  return db.listTargets().filter((t) => {
    if (!t.active) return false;
    const last = db.lastCheck(t.id);
    // a new target is due right away (first check should not wait a full interval)
    const since = last ? last.ts : t.created_at - t.interval_seconds * 1000;
    return now - since >= Math.max(5, t.interval_seconds) * 1000;
  });
}

async function tick() {
  if (running) return;
  running = true;
  try {
    const targets = dueTargets(Date.now());
    for (const target of targets) {
      try {
        await checker.performCheck(target.id);
      } catch (err) {
        console.error(`[scheduler] check failed for ${target.name}: ${err.message}`);
      }
    }
  } finally {
    running = false;
  }
}

function start() {
  if (timer) return;
  timer = setInterval(() => { tick().catch(() => {}); }, TICK_MS);
  if (timer.unref) timer.unref();
  console.log(`[scheduler] running every ${TICK_MS}ms`);
}

function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

module.exports = { start, stop, tick };
