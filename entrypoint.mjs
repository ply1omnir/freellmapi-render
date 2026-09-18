// entrypoint.mjs — container entrypoint for FreeLLMAPI on Render's free tier.
//
// This single process does two jobs:
//
//   1. RECEIVER — serves the app's own encrypted database backups over
//      loopback (127.0.0.1) and republishes them to GitHub Releases, where
//      assets are deletable (unlike git history) so retention keeps the
//      repository bounded forever.
//
//   2. SUPERVISOR — probes GitHub before starting the app, so the app's own
//      boot-time restore finds a backup waiting at the loopback URL, then
//      supervises the app process.
//
// SECURITY / TRUST BOUNDARIES (deliberate, do not loosen casually):
//   * The receiver binds 127.0.0.1 ONLY. It is never part of the public
//     surface. Render routes exactly one port ($PORT) to the internet, and
//     that port belongs to the app.
//   * Both GET and PUT require the shared bearer token, compared in constant
//     time. The token never appears in a response body or a log line.
//   * Backups are relayed as opaque BYTES. This process never decrypts them
//     and holds no key, so it cannot leak database contents.
//   * On unrecoverable boot failure the container serves a minimal 500 page on
//     $PORT instead of starting the app. Starting the app on an empty database
//     would make it overwrite the good backup minutes later.
//   * No stack traces, no secret values, and no upstream response bodies are
//     exposed to the public 500 page.

import http from "node:http";
import { spawn } from "node:child_process";
import {
  configRepo,
  deleteRelease,
  downloadAsset,
  latestSnapshot,
  listSnapshots,
  publishSnapshot,
  requiredToken,
  tagToDate,
  tsTag,
} from "./github.mjs";

const PORT = Number(process.env.PORT || 10000);
const RECEIVER_PORT = Number(process.env.RECEIVER_PORT || 8787);
const APP_ENTRY = process.env.APP_ENTRY || "server/dist/index.js";
const APP_CWD = process.env.APP_CWD || "/app";
const APP_DATA_DIR = process.env.APP_DATA_DIR || "/app/server/data";
const BACKUP_TOKEN = (process.env.BACKUP_TOKEN || process.env.FREEAPI_DB_BACKUP_TOKEN || "").trim();
const BACKUP_INTERVAL_MS = process.env.FREEAPI_DB_BACKUP_INTERVAL_MS || "900000";
const ASSET_NAME = process.env.BACKUP_ASSET_NAME || "freellmapi-backup.bin";

const KEEP_RECENT = Number(process.env.KEEP_RECENT || 128);
const KEEP_DAYS = Number(process.env.KEEP_DAYS || 128);
const KEEP_WEEKS = Number(process.env.KEEP_WEEKS || 128);
const MAX_BODY_BYTES = 64 * 1024 * 1024;
const BOOT_DELAYS_MS = [5000, 10000, 20000, 30000, 30000, 30000];
const DAY_MS = 24 * 60 * 60 * 1000;

const state = {
  startedAt: new Date().toISOString(),
  boot: "pending",
  bootError: null,
  loadedTag: null,
  payload: null,
  putCount: 0,
  publishOk: 0,
  publishFail: 0,
  lastPutAt: null,
  lastPublishAt: null,
  lastError: null,
  appPid: null,
  appExits: 0,
  fastExits: 0,
  degraded: false,
};

function log(msg) {
  process.stdout.write("[entrypoint] " + new Date().toISOString() + " " + msg + "\n");
}

// Never let a secret reach a log line or an HTTP response.
function scrub(text) {
  let out = String(text == null ? "" : text);
  for (const secret of [BACKUP_TOKEN, process.env.GITHUB_TOKEN]) {
    if (secret && secret.length >= 8) out = out.split(secret).join("***REDACTED***");
  }
  return out;
}

function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

function constantEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── retention: keep newest N + N days + N weeks ──────────────────────────────
function isoWeekKey(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNum = (d.getUTCDay() + 6) % 7;
  d.setUTCDate(d.getUTCDate() - dayNum + 3);
  const firstThursday = new Date(Date.UTC(d.getUTCFullYear(), 0, 4));
  const fDayNum = (firstThursday.getUTCDay() + 6) % 7;
  firstThursday.setUTCDate(firstThursday.getUTCDate() - fDayNum + 3);
  const week = 1 + Math.round((d.getTime() - firstThursday.getTime()) / (7 * DAY_MS));
  return String(d.getUTCFullYear()) + "-W" + String(week).padStart(2, "0");
}

function dayKey(date) {
  return date.toISOString().slice(0, 10);
}

async function sweepRetention() {
  const all = await listSnapshots();
  const keep = new Set();
  for (let i = 0; i < Math.min(KEEP_RECENT, all.length); i++) keep.add(all[i].id);

  const byDay = new Map();
  const byWeek = new Map();
  for (const rel of all) {
    const d = tagToDate(rel.tag);
    if (!d) continue;
    const dk = dayKey(d);
    if (!byDay.has(dk)) byDay.set(dk, rel);
    const wk = isoWeekKey(d);
    if (!byWeek.has(wk)) byWeek.set(wk, rel);
  }
  const days = Array.from(byDay.keys()).sort().reverse().slice(0, KEEP_DAYS);
  for (const k of days) keep.add(byDay.get(k).id);
  const weeks = Array.from(byWeek.keys()).sort().reverse().slice(0, KEEP_WEEKS);
  for (const k of weeks) keep.add(byWeek.get(k).id);

  const repo = configRepo();
  const doomed = all.filter(function (r) {
    return !keep.has(r.id);
  });
  let deleted = 0;
  for (const rel of doomed) {
    try {
      await deleteRelease(rel.id);
      await ghDeleteTag(repo, rel.tag);
      deleted++;
    } catch (e) {
      // best effort — never fail a good backup because pruning hiccuped
    }
  }
  return { total: all.length, kept: all.length - deleted, deleted: deleted };
}

async function ghDeleteTag(repo, tag) {
  const res = await fetch("https://api.github.com/repos/" + repo + "/git/refs/tags/" + encodeURIComponent(tag), {
    method: "DELETE",
    headers: {
      Authorization: "Bearer " + requiredToken(),
      Accept: "application/vnd.github+json",
      "User-Agent": "freellmapi-render-entrypoint",
    },
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok && res.status !== 404) throw new Error("tag delete " + res.status);
}

async function publish(payload) {
  const tag = tsTag("snap-", new Date());
  const body =
    "app: freellmapi\n" +
    "encrypted: yes (AES-256-GCM, produced by the app)\n" +
    "bytes: " + payload.length + "\n" +
    "createdAt: " + new Date().toISOString() + "\n";
  const res = await publishSnapshot(tag, body, payload, ASSET_NAME);
  state.publishOk++;
  state.lastPublishAt = new Date().toISOString();
  log("published " + tag + " (" + payload.length + " bytes, asset " + res.assetId + ")");
  try {
    const sweep = await sweepRetention();
    log("retention: " + JSON.stringify(sweep));
  } catch (err) {
    log("retention failed: " + scrub(err && err.message ? err.message : err));
  }
  return res;
}

// ── boot probe ───────────────────────────────────────────────────────────────
// The app's own backup format: magic "FAPIBK1\0" + iv(12) + tag(16) + ciphertext.
// We never decrypt, but we DO verify the magic: serving a foreign or truncated
// artifact to the app makes it refuse to start (correctly, fail-closed), which
// without this check turns into an endless crash-restart loop.
const BACKUP_MAGIC = Buffer.from("FAPIBK1\u0000", "binary");
const MIN_BACKUP_BYTES = 7 + 12 + 16;

function looksLikeAppBackup(buf) {
  return (
    Buffer.isBuffer(buf) &&
    buf.length >= MIN_BACKUP_BYTES &&
    buf.subarray(0, BACKUP_MAGIC.length).equals(BACKUP_MAGIC)
  );
}

async function bootProbe() {
  for (let attempt = 0; attempt <= BOOT_DELAYS_MS.length; attempt++) {
    try {
      const all = await listSnapshots();
      const withAssets = all.filter(function (r) {
        return r.assets.length > 0;
      });
      if (withAssets.length === 0) {
        // A reachable repository that simply holds no backup yet.
        log("no backup in " + configRepo() + " yet — treating as FIRST BOOT");
        state.boot = "first-boot";
        return;
      }
      const rejected = [];
      for (const rel of withAssets) {
        const buf = await downloadAsset(rel.assets[0].id);
        if (looksLikeAppBackup(buf)) {
          state.payload = buf;
          state.loadedTag = rel.tag;
          state.boot = "loaded";
          log("loaded backup " + rel.tag + " (" + buf.length + " bytes)");
          return;
        }
        rejected.push(rel.tag);
        log("skipping " + rel.tag + ": not a FreeLLMAPI backup (bad magic)");
      }
      // Assets exist but none is a usable backup. Starting the app now would
      // run it on an empty database and let it overwrite a good backup later,
      // so this is a hard stop that needs a human.
      throw new Error(
        "found " + withAssets.length + " asset(s) but none is a valid backup: " + rejected.join(", ")
      );
    } catch (err) {
      state.bootError = scrub(err && err.message ? err.message : err);
      log("boot probe attempt " + (attempt + 1) + " failed: " + state.bootError);
      if (attempt < BOOT_DELAYS_MS.length) await sleep(BOOT_DELAYS_MS[attempt]);
    }
  }
  state.boot = "degraded";
  state.degraded = true;
  log("BOOT PROBE EXHAUSTED — entering degraded mode, the app will NOT start");
}

// ── receiver (loopback only) ─────────────────────────────────────────────────
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
}

function authorized(req) {
  if (!BACKUP_TOKEN) return false;
  const supplied = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  return constantEquals(supplied, BACKUP_TOKEN);
}

function startReceiver() {
  const server = http.createServer(function (req, res) {
    const url = new URL(req.url || "/", "http://127.0.0.1");
    if (url.pathname !== "/backup") {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    if (!authorized(req)) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
    if (req.method === "GET") {
      if (!state.payload) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("no backup available");
        return;
      }
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(state.payload.length),
        "Cache-Control": "no-store",
      });
      res.end(state.payload);
      return;
    }
    if (req.method === "PUT") {
      const chunks = [];
      let total = 0;
      let aborted = false;
      req.on("data", function (c) {
        total += c.length;
        if (total > MAX_BODY_BYTES) {
          aborted = true;
          sendJson(res, 413, { error: "payload too large" });
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", function () {
        if (aborted) return;
        const payload = Buffer.concat(chunks);
        if (payload.length === 0) {
          sendJson(res, 400, { error: "empty body" });
          return;
        }
        state.payload = payload;
        state.putCount++;
        state.lastPutAt = new Date().toISOString();
        log("received backup #" + state.putCount + " (" + payload.length + " bytes)");
        // Publish synchronously so the response tells the truth about
        // durability. The app's own PUT timeout is 30s; a GitHub publish is
        // normally 1-3s, and on failure we still keep the in-memory copy.
        publish(payload)
          .then(function () {
            sendJson(res, 200, { ok: true, bytes: payload.length, published: true });
          })
          .catch(function (err) {
            state.publishFail++;
            state.lastError = scrub(err && err.message ? err.message : err);
            log("publish failed: " + state.lastError);
            sendJson(res, 200, { ok: true, bytes: payload.length, published: false });
          });
      });
      return;
    }
    sendJson(res, 405, { error: "method not allowed" });
  });
  server.on("clientError", function (_e, socket) {
    try {
      socket.destroy();
    } catch (e) {
      // ignore
    }
  });
  server.listen(RECEIVER_PORT, "127.0.0.1", function () {
    log("receiver listening on 127.0.0.1:" + RECEIVER_PORT + " (loopback only)");
    if (!BACKUP_TOKEN) log("WARNING: BACKUP_TOKEN is not set — every backup request will be rejected");
  });
  return server;
}

function startStatusServer() {
  // Internal-only diagnostics on another loopback port: never the public port.
  const s = http.createServer(function (req, res) {
    sendJson(res, 200, {
      boot: state.boot,
      bootError: state.bootError,
      loadedTag: state.loadedTag,
      hasPayload: !!state.payload,
      payloadBytes: state.payload ? state.payload.length : null,
      putCount: state.putCount,
      publishOk: state.publishOk,
      publishFail: state.publishFail,
      lastPutAt: state.lastPutAt,
      lastPublishAt: state.lastPublishAt,
      lastError: state.lastError,
      appPid: state.appPid,
      appExits: state.appExits,
      uptimeSec: Math.round(process.uptime()),
    });
  });
  s.listen(RECEIVER_PORT + 1, "127.0.0.1", function () {
    log("status listening on 127.0.0.1:" + (RECEIVER_PORT + 1));
  });
  return s;
}

// ── degraded mode ────────────────────────────────────────────────────────────
function startDegradedServer() {
  const page =
    "<!doctype html><meta charset=utf-8><title>503</title>" +
    "<h1>Service unavailable</h1>" +
    "<p>This instance could not load its configuration backup from GitHub and " +
    "refused to start, to avoid overwriting a good backup with an empty database.</p>" +
    "<p>Reason: " + scrub(state.bootError || "unknown").replace(/[<>&]/g, "") + "</p>" +
    "<p>Started: " + state.startedAt + "</p>";
  const server = http.createServer(function (_req, res) {
    res.writeHead(500, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(page);
  });
  server.listen(PORT, "0.0.0.0", function () {
    log("DEGRADED: serving 500 on 0.0.0.0:" + PORT + " — the app was not started");
  });
  return server;
}

// ── app supervision ──────────────────────────────────────────────────────────
let app = null;
let shuttingDown = false;

function startApp() {
  const childEnv = Object.assign({}, process.env, {
    PORT: String(PORT),
    HOSTNAME: "0.0.0.0",
    DATA_DIR: APP_DATA_DIR,
    FREEAPI_DB_BACKUP_TARGET: "http://127.0.0.1:" + RECEIVER_PORT + "/backup",
    FREEAPI_DB_BACKUP_TOKEN: BACKUP_TOKEN,
    FREEAPI_DB_BACKUP_INTERVAL_MS: String(BACKUP_INTERVAL_MS),
  });
  const startedAt = Date.now();
  app = spawn(process.execPath, [APP_ENTRY], { cwd: APP_CWD, env: childEnv, stdio: "inherit" });
  state.appPid = app.pid;
  log("app started pid=" + app.pid + " on port " + PORT + " (backup interval " + BACKUP_INTERVAL_MS + "ms)");
  app.on("exit", function (code, signal) {
    state.appExits++;
    state.appPid = null;
    const uptimeMs = Date.now() - startedAt;
    log("app exited code=" + code + " signal=" + signal + " after " + Math.round(uptimeMs / 1000) + "s");
    if (shuttingDown) return;
    // Back off on repeated fast failures: a crash loop that respawns every 3s
    // burns the instance and floods the logs without ever getting healthier.
    if (uptimeMs < 15000) {
      state.fastExits++;
    } else {
      state.fastExits = 0;
    }
    const delay = Math.min(60000, 3000 * Math.pow(2, Math.min(state.fastExits, 4)));
    log("restarting app in " + Math.round(delay / 1000) + "s (consecutive fast exits: " + state.fastExits + ")");
    setTimeout(startApp, delay);
  });
}

function shutdown(reason) {
  if (shuttingDown) return;
  shuttingDown = true;
  log("shutdown (" + reason + ")");
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
  log("booting: PORT=" + PORT + " receiver=127.0.0.1:" + RECEIVER_PORT + " repo=" + (process.env.GITHUB_CONFIG_REPO || "(unset)"));
  await bootProbe();
  if (state.degraded) {
    startDegradedServer();
    return;
  }
  startReceiver();
  startStatusServer();
  startApp();
}

main().catch(function (err) {
  log("FATAL: " + scrub(err && err.stack ? err.stack : err));
  startDegradedServer();
});
