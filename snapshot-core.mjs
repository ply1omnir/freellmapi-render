// snapshot-core.mjs — take a consistent, pruned, gzipped snapshot of the
// OmniRoute SQLite database and publish it as a GitHub Release asset.
//
// IMPORTANT: this runs IN-PROCESS inside the supervisor, not as a child Node
// process. Measured on Render's free tier (512Mi): running the snapshot in a
// third Node process pushed the container over its memory limit and Render
// OOM-killed the instance. In-process the extra cost is only the DB copy plus
// the gzip buffer (a few MB), not a whole Node runtime.
//
// The synchronous parts below (prune + VACUUM + gzip) block the supervisor's
// event loop for well under a second on a database this size, which is an
// acceptable trade for not being OOM-killed.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { createRequire } from "node:module";
import {
  AUTO_PREFIX,
  MANUAL_PREFIX,
  configRepo,
  deleteRelease,
  gh,
  listSnapshots,
  publishSnapshot,
  tagToDate,
  tsTag,
} from "./github.mjs";

const require = createRequire(import.meta.url);

const DATA_DIR = process.env.DATA_DIR || "/app/data";
// The database filename differs per app (OmniRoute: storage.sqlite,
// FreeLLMAPI: freellmapi.db), so it is configurable.
const DB_PATH = path.join(DATA_DIR, process.env.DB_FILENAME || "storage.sqlite");
const ASSET_NAME = "omniroute-config.sqlite.gz";
const MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024;
const KEEP_AUTO_DAYS = 100;
const KEEP_AUTO_WEEKS = 100;
const DAY_MS = 24 * 60 * 60 * 1000;

// Conservative denylist: only logs, telemetry, caches and other disposable
// runtime state. Anything not listed is preserved, so a missing entry can only
// cost a little space — never a piece of configuration.
const RUNTIME_TABLES = [
  "usage_history", "daily_usage_summary", "hourly_usage_summary", "token_ledger",
  "call_logs", "request_detail_logs", "relay_logs", "middleware_logs", "proxy_logs",
  "routing_decisions", "domain_cost_history", "domain_budget_reset_logs",
  "compression_analytics", "compression_cache_stats", "quota_snapshots",
  "quota_consumption", "provider_quota_state", "provider_quota_reset_events",
  "api_key_token_counters", "api_key_token_limit_reset_logs", "semantic_cache",
  "reasoning_cache", "session_model_history", "session_account_affinity",
  "conversation_turn_nodes", "agentic_conversations", "mcp_tool_audit",
  "skill_executions", "plugin_analytics", "plugin_metrics", "audit_log",
  "config_audit_log", "xp_audit_log", "radar_feed_cache", "radar_intel_cache",
  "radar_offers_cache", "radar_referrals_cache", "radar_local_model_state",
  "inspector_session_requests", "inspector_sessions", "job_runs", "eval_runs",
  "discovery_results", "free_proxy_sync_errors", "webhook_deliveries",
  "connection_runtime_state", "agent_bridge_state", "combo_adaptation_state",
  "exclusive_connection_leases", "relay_rate_limits", "proxy_scope_rotation",
  "a2a_task_events", "a2a_tasks", "leaderboard", "tier_assignments",
  "user_badges", "user_levels",
];

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

function pruneAndVacuum(sqlitePath, tables) {
  const Database = require("better-sqlite3");
  const db = new Database(sqlitePath);
  const cleared = {};
  try {
    db.pragma("journal_mode = DELETE");
    const present = new Set(
      db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(function (r) {
        return r.name;
      })
    );
    const tx = db.transaction(function () {
      for (const t of tables) {
        if (!present.has(t)) continue;
        try {
          const info = db.prepare('DELETE FROM "' + t + '"').run();
          if (info.changes > 0) cleared[t] = info.changes;
        } catch (e) {
          // Virtual/protected tables are skipped; never fail a snapshot for them.
        }
      }
    });
    tx();
    db.exec("VACUUM");
  } finally {
    db.close();
  }
  return cleared;
}

export async function sweepRetention() {
  const all = await listSnapshots();
  const manual = all.filter(function (r) {
    return r.manual;
  });
  const auto = all.filter(function (r) {
    return !r.manual;
  });
  const keep = new Set();
  for (const r of manual) keep.add(r.id);

  const now = Date.now();
  for (const r of auto) {
    const d = tagToDate(r.tag);
    if (d && now - d.getTime() <= KEEP_AUTO_DAYS * DAY_MS) keep.add(r.id);
  }

  const byWeek = new Map();
  for (const r of auto) {
    const d = tagToDate(r.tag);
    if (!d) continue;
    const k = isoWeekKey(d);
    if (!byWeek.has(k)) byWeek.set(k, r);
  }
  const weeks = Array.from(byWeek.keys()).sort().reverse().slice(0, KEEP_AUTO_WEEKS);
  for (const k of weeks) keep.add(byWeek.get(k).id);

  const doomed = auto.filter(function (r) {
    return !keep.has(r.id);
  });
  const repo = configRepo();
  let deleted = 0;
  for (const r of doomed) {
    try {
      await deleteRelease(r.id);
      await gh("/repos/" + repo + "/git/refs/tags/" + encodeURIComponent(r.tag), {
        method: "DELETE",
      });
      deleted++;
    } catch (e) {
      // Retention is best-effort and must never fail a successful snapshot.
    }
  }
  return {
    total: all.length,
    manual: manual.length,
    auto: auto.length,
    kept: all.length - deleted,
    deleted: deleted,
  };
}

/** Take and publish one snapshot. Returns a result object; never throws. */
// Per-app override. OmniRoute needs a denylist of its runtime tables; a lighter
// app may need none at all. An explicitly empty PRUNE_TABLES disables pruning.
function runtimeTables() {
  const raw = process.env.PRUNE_TABLES;
  if (raw === undefined) return RUNTIME_TABLES;
  return raw
    .split(",")
    .map(function (s) {
      return s.trim();
    })
    .filter(Boolean);
}

export async function performSnapshot(mode) {
  const kind = mode === "manual" ? "manual" : "auto";
  const started = Date.now();
  const result = { ok: false, mode: kind, steps: {} };
  if (!fs.existsSync(DB_PATH)) {
    result.error = "database not found at " + DB_PATH;
    return result;
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "omni-snap-"));
  const tmpDb = path.join(tmpDir, "snapshot.sqlite");
  try {
    const Database = require("better-sqlite3");
    const live = new Database(DB_PATH, { readonly: false });
    try {
      await live.backup(tmpDb);
    } finally {
      live.close();
    }
    result.steps.rawBytes = fs.statSync(tmpDb).size;

    const cleared = pruneAndVacuum(tmpDb, runtimeTables());
    result.steps.pruned = Object.keys(cleared).length;
    result.steps.prunedBytes = fs.statSync(tmpDb).size;

    const gz = zlib.gzipSync(fs.readFileSync(tmpDb), { level: 9 });
    result.steps.gzBytes = gz.length;
    if (gz.length > MAX_SNAPSHOT_BYTES) {
      throw new Error("snapshot too large: " + gz.length + " > " + MAX_SNAPSHOT_BYTES);
    }

    const prefix = kind === "manual" ? MANUAL_PREFIX : AUTO_PREFIX;
    const tag = tsTag(prefix);
    const body =
      "mode: " + kind +
      "\nraw: " + result.steps.rawBytes +
      "\npruned: " + result.steps.prunedBytes +
      "\ngz: " + result.steps.gzBytes +
      "\ncreatedAt: " + new Date().toISOString() + "\n";
    result.steps.published = await publishSnapshot(tag, body, gz, ASSET_NAME);
    if (kind === "auto") result.steps.retention = await sweepRetention();
    result.ok = true;
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (e) {
      // ignore
    }
  }
  result.ms = Date.now() - started;
  return result;
}
