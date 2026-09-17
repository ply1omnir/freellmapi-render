// supervisor.mjs — container entrypoint for OmniRoute on Render's free tier.
//
// Why this exists: a Render free web service has an ephemeral filesystem and no
// shell access. This supervisor gives us the three things the platform does not:
//
//   1. restore  — rebuild /app/data/storage.sqlite from the newest snapshot in
//                 the private config repo before OmniRoute ever starts;
//   2. snapshot — run a scheduled (and manually triggerable) snapshot process
//                 that publishes to GitHub Releases;
//   3. control  — a token-gated narrow endpoint, reachable through the single
//                 public port, so a human can trigger a snapshot from a browser
//                 without any shell.
//
// It deliberately does NOT provide a general-purpose shell or command executor.

import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { spawn } from "node:child_process";
import { downloadAsset, latestSnapshot, tagToDate } from "./github.mjs";
import { performSnapshot } from "./snapshot-core.mjs";

const PORT = Number(process.env.PORT || 10000);
const APP_PORT = Number(process.env.APP_PORT || 20128);
const DATA_DIR = process.env.DATA_DIR || "/app/data";
const DB_PATH = path.join(DATA_DIR, "storage.sqlite");
const APP_ENTRY = process.env.APP_ENTRY || "dev/run-standalone.mjs";
const APP_CWD = process.env.APP_CWD || "/app";
const CONTROL_TOKEN = (process.env.CONTROL_TOKEN || "").trim();
const AUTO_CHECK_MS = 60 * 60 * 1000;
const AUTO_MIN_AGE_MS = 20 * 60 * 60 * 1000;

const state = {
  startedAt: new Date().toISOString(),
  restored: null,
  restoreError: null,
  appPid: null,
  appExits: 0,
  lastSnapshot: null,
  snapshotsRunning: 0,
};

function log(msg) {
  process.stdout.write("[supervisor] " + new Date().toISOString() + " " + msg + "\n");
}

function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

// ── 1. restore ──────────────────────────────────────────────────────────────
async function restore() {
  if (fs.existsSync(DB_PATH)) {
    log("database already present, skipping restore: " + DB_PATH);
    state.restored = "present";
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const rel = await latestSnapshot();
      if (!rel) {
        log("no snapshot release found; starting with a fresh database");
        state.restored = "fresh";
        return;
      }
      const asset = rel.assets[0];
      log("restoring from " + rel.tag + " (asset " + asset.id + ", " + asset.size + " bytes)");
      const buf = await downloadAsset(asset.id);
      const raw = zlib.gunzipSync(buf);
      const tmp = DB_PATH + ".restore";
      fs.writeFileSync(tmp, raw);
      fs.renameSync(tmp, DB_PATH);
      state.restored = rel.tag;
      log("restored " + raw.length + " bytes into " + DB_PATH);
      return;
    } catch (err) {
      state.restoreError = err && err.message ? err.message : String(err);
      log("restore attempt " + attempt + " failed: " + state.restoreError);
      if (attempt < 3) await sleep(2000 * attempt);
    }
  }
  log("RESTORE FAILED — starting with an empty database. Manual attention required.");
  state.restored = "failed";
}

// ── 2. snapshot trigger ─────────────────────────────────────────────────────
async function runSnapshot(mode) {
  // Runs IN-PROCESS on purpose: a third Node process for the snapshot was
  // measured to push this 512Mi container into a Render OOM kill.
  state.snapshotsRunning++;
  try {
    const parsed = await performSnapshot(mode);
    state.lastSnapshot = { at: new Date().toISOString(), mode: mode, result: parsed };
    log("snapshot(" + mode + ") finished: " + JSON.stringify(parsed).slice(0, 400));
    return parsed;
  } catch (err) {
    const parsed = { ok: false, error: err && err.message ? err.message : String(err) };
    state.lastSnapshot = { at: new Date().toISOString(), mode: mode, result: parsed };
    log("snapshot(" + mode + ") threw: " + parsed.error);
    return parsed;
  } finally {
    state.snapshotsRunning--;
  }
}

async function maybeDailySnapshot() {
  try {
    const rel = await latestSnapshot();
    if (rel) {
      const d = tagToDate(rel.tag);
      if (d && !rel.manual && Date.now() - d.getTime() < AUTO_MIN_AGE_MS) return;
      if (d && rel.manual && Date.now() - d.getTime() < AUTO_MIN_AGE_MS) {
        // A manual snapshot already covers this window for the daily cadence.
        return;
      }
    }
    await runSnapshot("auto");
  } catch (err) {
    log("scheduled snapshot check failed: " + (err && err.message ? err.message : String(err)));
  }
}

// ── 3. control endpoints ────────────────────────────────────────────────────
function constantEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function fmtBytes(n) {
  if (!Number.isFinite(n)) return String(n);
  return Math.round(n / 1048576) + " MiB";
}

// Container-level memory picture. Render's free instance caps the container at
// 512 MiB, and the only way to see the real breakdown (who is eating it) is to
// read the cgroup counters and per-process RSS from inside the container.
function readMemoryReport() {
  const out = { meminfo: {}, cgroup: {}, processes: [], supervisor: null, appHeapLimitMb: null };
  try {
    const mi = fs.readFileSync("/proc/meminfo", "utf8");
    for (const line of mi.split("\n")) {
      const m = /^(MemTotal|MemAvailable|MemFree|SwapTotal|SwapFree):\s+(\d+)\s*kB/.exec(line);
      if (m) out.meminfo[m[1]] = fmtBytes(Number(m[2]) * 1024);
    }
  } catch (e) {
    out.meminfo.error = String(e.message || e);
  }
  const cg = [
    ["v2_current", "/sys/fs/cgroup/memory.current"],
    ["v2_max", "/sys/fs/cgroup/memory.max"],
    ["v2_peak", "/sys/fs/cgroup/memory.peak"],
    ["v1_usage", "/sys/fs/cgroup/memory/memory.usage_in_bytes"],
    ["v1_limit", "/sys/fs/cgroup/memory/memory.limit_in_bytes"],
  ];
  for (const pair of cg) {
    try {
      const raw = fs.readFileSync(pair[1], "utf8").trim();
      out.cgroup[pair[0]] = raw === "max" ? "max" : fmtBytes(Number(raw));
    } catch (e) {
      // not present on this cgroup version
    }
  }
  try {
    for (const d of fs.readdirSync("/proc")) {
      if (!/^[0-9]+$/.test(d)) continue;
      try {
        const st = fs.readFileSync("/proc/" + d + "/status", "utf8");
        const nameM = /^Name:\s+(.+)$/m.exec(st);
        const rssM = /^VmRSS:\s+([0-9]+)\s+kB/m.exec(st);
        const rss = rssM ? Number(rssM[1]) : 0;
        if (rss > 0) {
          out.processes.push({ pid: Number(d), name: nameM ? nameM[1] : "?", rssMiB: Math.round(rss / 1024) });
        }
      } catch (e) {
        // process vanished
      }
    }
    out.processes.sort(function (a, b) {
      return b.rssMiB - a.rssMiB;
    });
  } catch (e) {
    out.processesError = String(e.message || e);
  }
  const mu = process.memoryUsage();
  out.supervisor = {
    rssMiB: Math.round(mu.rss / 1048576),
    heapUsedMiB: Math.round(mu.heapUsed / 1048576),
    heapTotalMiB: Math.round(mu.heapTotal / 1048576),
    externalMiB: Math.round((mu.external || 0) / 1048576),
  };
  out.appHeapLimitMb = process.env.OMNIROUTE_MEMORY_MB || null;
  out.appPid = state.appPid;
  return out;
}

async function handleControl(req, res, url) {
  if (!CONTROL_TOKEN) {
    sendJson(res, 503, { error: "control endpoint disabled: CONTROL_TOKEN not configured" });
    return true;
  }
  const supplied =
    url.searchParams.get("token") ||
    (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!constantEquals(supplied, CONTROL_TOKEN)) {
    sendJson(res, 401, { error: "unauthorized" });
    return true;
  }
  const action = url.pathname.replace(/^\/__control\/?/, "");
  if (action === "" || action === "status") {
    sendJson(res, 200, {
      ok: true,
      startedAt: state.startedAt,
      uptimeSec: Math.round(process.uptime()),
      appPid: state.appPid,
      appExits: state.appExits,
      restored: state.restored,
      restoreError: state.restoreError,
      database: fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : null,
      snapshotsRunning: state.snapshotsRunning,
      lastSnapshot: state.lastSnapshot,
    });
    return true;
  }
  if (action === "snapshot" || action === "snapshot-manual") {
    const result = await runSnapshot("manual");
    sendJson(res, result && result.ok ? 200 : 500, {
      requested: "manual snapshot",
      result: result,
    });
    return true;
  }
  if (action === "mem" || action === "memory") {
    sendJson(res, 200, readMemoryReport());
    return true;
  }
  if (action === "restore-info") {
    const rel = await latestSnapshot();
    sendJson(res, 200, { restored: state.restored, latest: rel });
    return true;
  }
  sendJson(res, 404, { error: "unknown control action", action: action });
  return true;
}

// ── 4. reverse proxy (HTTP + WebSocket) ─────────────────────────────────────
function proxyHttp(req, res) {
  const upstream = http.request(
    {
      host: "127.0.0.1",
      port: APP_PORT,
      method: req.method,
      path: req.url,
      headers: req.headers,
    },
    function (upRes) {
      res.writeHead(upRes.statusCode || 502, upRes.headers);
      upRes.pipe(res);
    }
  );
  upstream.on("error", function (err) {
    if (!res.headersSent) {
      sendJson(res, 502, { error: "upstream unavailable", detail: err.message });
    } else {
      res.end();
    }
  });
  req.pipe(upstream);
}

function proxyUpgrade(req, socket, head) {
  const upstream = net.connect(APP_PORT, "127.0.0.1", function () {
    let raw = req.method + " " + req.url + " HTTP/1.1\r\n";
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      raw += req.rawHeaders[i] + ": " + req.rawHeaders[i + 1] + "\r\n";
    }
    raw += "\r\n";
    upstream.write(raw);
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on("error", function () {
    try {
      socket.destroy();
    } catch (e) {
      // ignore
    }
  });
  socket.on("error", function () {
    try {
      upstream.destroy();
    } catch (e) {
      // ignore
    }
  });
}

const server = http.createServer(function (req, res) {
  const url = new URL(req.url || "/", "http://localhost");
  if (url.pathname.startsWith("/__control")) {
    handleControl(req, res, url).catch(function (err) {
      sendJson(res, 500, { error: err && err.message ? err.message : String(err) });
    });
    return;
  }
  proxyHttp(req, res);
});
server.on("upgrade", proxyUpgrade);
server.on("clientError", function (err, socket) {
  try {
    socket.destroy();
  } catch (e) {
    // ignore
  }
});

// ── 5. app process ──────────────────────────────────────────────────────────
function startApp() {
  const childEnv = Object.assign({}, process.env, {
    PORT: String(APP_PORT),
    DASHBOARD_PORT: String(APP_PORT),
    API_PORT: String(APP_PORT),
    HOSTNAME: "0.0.0.0",
    DATA_DIR: DATA_DIR,
  });
  const child = spawn(process.execPath, [APP_ENTRY], {
    cwd: APP_CWD,
    env: childEnv,
    stdio: "inherit",
  });
  state.appPid = child.pid;
  log("OmniRoute started pid=" + child.pid + " on 127.0.0.1:" + APP_PORT);
  child.on("exit", function (code, signal) {
    state.appExits++;
    state.appPid = null;
    log("OmniRoute exited code=" + code + " signal=" + signal);
    if (!shuttingDown) {
      log("restarting OmniRoute in 3s");
      setTimeout(startApp, 3000);
    }
  });
  return child;
}

let app = null;
let shuttingDown = false;

async function shutdown(reason) {
  if (shuttingDown) return;
  shuttingDown = true;
  log("shutdown requested (" + reason + ") — taking a final snapshot");
  try {
    await Promise.race([runSnapshot("auto"), sleep(25000)]);
  } catch (err) {
    log("final snapshot failed: " + (err && err.message ? err.message : String(err)));
  }
  if (app && !app.killed) {
    try {
      app.kill("SIGTERM");
    } catch (e) {
      // ignore
    }
  }
  setTimeout(function () {
    process.exit(0);
  }, 1500);
}

process.on("SIGTERM", function () {
  shutdown("SIGTERM");
});
process.on("SIGINT", function () {
  shutdown("SIGINT");
});

async function main() {
  log("booting: PORT=" + PORT + " APP_PORT=" + APP_PORT + " DATA_DIR=" + DATA_DIR);
  await restore();
  app = startApp();
  server.listen(PORT, "0.0.0.0", function () {
    log("control/proxy listening on 0.0.0.0:" + PORT);
    if (!CONTROL_TOKEN) {
      log("WARNING: CONTROL_TOKEN not set — manual snapshot endpoint is disabled");
    }
  });
  // Delay the first scheduled snapshot: the app needs its startup memory
  // headroom first, and an immediate snapshot stacks a third process on top.
  setTimeout(maybeDailySnapshot, 10 * 60 * 1000);
  setInterval(maybeDailySnapshot, AUTO_CHECK_MS);
}

main().catch(function (err) {
  log("FATAL: " + (err && err.stack ? err.stack : String(err)));
  process.exit(1);
});
