"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const state = { targets: [] };

  async function api(path, opts) {
    const res = await fetch(path, opts);
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  function timeAgo(ts) {
    if (!ts) return "never";
    const s = Math.round((Date.now() - ts) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    return `${Math.round(s / 3600)}h ago`;
  }

  function renderSpark(spark) {
    const wrap = document.createElement("div");
    wrap.className = "spark";
    const max = Math.max(...spark.map((p) => p.ms || 0), 100);
    for (const point of spark) {
      const bar = document.createElement("i");
      const h = Math.max(3, Math.round(((point.ms || 0) / max) * 20));
      bar.style.height = `${h}px`;
      if (!point.ok) bar.classList.add("bad");
      bar.title = `${point.ok ? "up" : "down"} · ${point.ms ?? "?"}ms`;
      wrap.appendChild(bar);
    }
    if (!spark.length) {
      const bar = document.createElement("i");
      bar.style.height = "3px";
      wrap.appendChild(bar);
    }
    return wrap;
  }

  function renderTargets() {
    const list = $("targets");
    list.innerHTML = "";
    $("empty").style.display = state.targets.length ? "none" : "block";

    for (const target of state.targets) {
      const row = document.createElement("div");
      row.className = "target";

      const top = document.createElement("div");
      top.className = "t-top";
      const dot = document.createElement("span");
      dot.className = `dot ${target.status}`;
      const info = document.createElement("div");
      info.style.minWidth = "0";
      const name = document.createElement("div");
      name.className = "t-name";
      name.textContent = target.name;
      const url = document.createElement("div");
      url.className = "t-url";
      url.textContent = target.url;
      info.appendChild(name);
      info.appendChild(url);

      const actions = document.createElement("div");
      actions.className = "t-actions";

      const checkBtn = document.createElement("button");
      checkBtn.className = "btn ghost small";
      checkBtn.type = "button";
      checkBtn.textContent = "CHECK NOW";
      checkBtn.addEventListener("click", async () => {
        checkBtn.disabled = true;
        checkBtn.textContent = "CHECKING…";
        await api(`/api/targets/${target.id}/check`, { method: "POST" });
        await refresh();
      });

      const del = document.createElement("button");
      del.className = "btn danger small";
      del.type = "button";
      del.textContent = "✕";
      del.title = "Stop monitoring";
      del.addEventListener("click", async () => {
        if (!window.confirm(`Delete monitor "${target.name}"?`)) return;
        await api(`/api/targets/${target.id}`, { method: "DELETE" });
        await refresh();
      });

      actions.appendChild(checkBtn);
      actions.appendChild(del);

      top.appendChild(dot);
      top.appendChild(info);
      top.appendChild(actions);

      const metrics = document.createElement("div");
      metrics.className = "t-metrics";

      const addMetric = (label, value, extra) => {
        const m = document.createElement("div");
        m.className = "metric";
        const l = document.createElement("span");
        l.textContent = label;
        m.appendChild(l);
        if (extra) {
          m.appendChild(extra);
        } else {
          const v = document.createElement("strong");
          v.textContent = value;
          m.appendChild(v);
        }
        metrics.appendChild(m);
      };

      addMetric("STATUS", target.status.toUpperCase());
      addMetric("UPTIME 24H", target.uptime24 === null ? "—" : `${target.uptime24}%`);
      addMetric("RESPONSE", target.lastCheck && target.lastCheck.response_ms !== null ? `${target.lastCheck.response_ms}ms` : "—");
      addMetric("LAST CHECK", timeAgo(target.lastCheck && target.lastCheck.ts));
      addMetric("INTERVAL", `${target.intervalSeconds}s`);

      if (target.security && target.security.grade) {
        const gradeEl = document.createElement("span");
        gradeEl.className = `grade ${target.security.grade}`;
        gradeEl.textContent = target.security.grade;
        addMetric("SECURITY", null, gradeEl);
      }

      if (target.security && target.security.tlsDays !== null && target.security.tlsDays !== undefined) {
        addMetric("TLS", `${target.security.tlsDays}d`);
      }

      const sparkMetric = document.createElement("div");
      sparkMetric.className = "metric";
      const sl = document.createElement("span");
      sl.textContent = "HISTORY";
      sparkMetric.appendChild(sl);
      sparkMetric.appendChild(renderSpark(target.sparkline || []));
      metrics.appendChild(sparkMetric);

      row.appendChild(top);
      row.appendChild(metrics);
      list.appendChild(row);
    }
  }

  function renderIncidents(incidents) {
    const wrap = $("incidents");
    wrap.innerHTML = "";
    if (!incidents.length) {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = "No incidents. Everything has been quiet.";
      wrap.appendChild(p);
      return;
    }
    for (const inc of incidents) {
      const el = document.createElement("div");
      el.className = "incident" + (inc.resolved_at ? " resolved" : "");
      const b = document.createElement("b");
      b.textContent = `${inc.target_name} — ${inc.resolved_at ? "recovered" : "DOWN"}`;
      const small = document.createElement("small");
      small.textContent = `${inc.reason || "check failed"} · ${timeAgo(inc.started_at)}${inc.resolved_at ? ` · resolved ${timeAgo(inc.resolved_at)}` : ""}`;
      el.appendChild(b);
      el.appendChild(small);
      wrap.appendChild(el);
    }
  }

  function renderFindings(targets) {
    const wrap = $("findings");
    wrap.innerHTML = "";
    const withSecurity = targets.filter((t) => t.security && t.security.findings && t.security.findings.length);
    if (!withSecurity.length) {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = "Run a check to see security header analysis.";
      wrap.appendChild(p);
      return;
    }
    for (const target of withSecurity.slice(0, 3)) {
      for (const f of target.security.findings.filter((x) => !x.ok).slice(0, 3)) {
        const row = document.createElement("div");
        row.className = "finding bad";
        const ic = document.createElement("span");
        ic.className = "ic";
        ic.textContent = "✕";
        const text = document.createElement("div");
        const b = document.createElement("b");
        b.textContent = `${target.name}: `;
        text.appendChild(b);
        text.appendChild(document.createTextNode(f.message));
        row.appendChild(ic);
        row.appendChild(text);
        wrap.appendChild(row);
      }
    }
    if (!wrap.children.length) {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = "All tracked headers look good. 🎉";
      wrap.appendChild(p);
    }
  }

  async function refresh() {
    const { body } = await api("/api/overview");
    state.targets = body.targets || [];
    $("s-monitors").textContent = body.totals.monitors;
    $("s-up").textContent = body.totals.up;
    $("s-down").textContent = body.totals.down;
    $("s-avg").textContent = body.totals.avgMs ? `${body.totals.avgMs}ms` : "—";
    renderTargets();
    renderIncidents(body.incidents || []);
    renderFindings(state.targets);
    $("last-refresh").textContent = "updated " + new Date().toLocaleTimeString();
  }

  /* ------------------------------------------------------------------- add */
  $("add-toggle").addEventListener("click", () => {
    $("add-form").classList.toggle("hidden");
    $("t-name").focus();
  });

  $("add-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      name: $("t-name").value.trim(),
      url: $("t-url").value.trim(),
      intervalSeconds: Number($("t-interval").value) || 60,
      expectedStatus: Number($("t-expected").value) || 200,
      webhook: $("t-webhook").value.trim()
    };
    if (!payload.name || !payload.url) {
      $("add-hint").textContent = "Name and URL are required.";
      return;
    }
    $("add-hint").textContent = "adding…";
    const { status, body } = await api("/api/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (status !== 201) {
      $("add-hint").textContent = body.error || "Failed to add.";
      return;
    }
    $("add-hint").textContent = "added ✓ running first check…";
    await api(`/api/targets/${body.target.id}/check`, { method: "POST" });
    $("t-name").value = "";
    $("t-url").value = "";
    $("t-webhook").value = "";
    $("add-hint").textContent = "";
    $("add-form").classList.add("hidden");
    await refresh();
  });

  $("refresh").addEventListener("click", refresh);

  refresh();
  setInterval(refresh, 5000);
})();
