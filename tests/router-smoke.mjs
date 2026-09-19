// Router smoke test: routing, fail-closed gate, safety block, header hygiene.
// Runs entirely with test doubles — no network, no real FreeLLMAPI, no real mitmdump.
// The entrypoint supervises the fake app itself (APP_ENTRY points at the double).
// Usage: node deploy/tests/router-smoke.mjs
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEPLOY = path.resolve(HERE, "..");
const FIX = path.join(HERE, "fixtures");

const PORT = 18081;
const APP_PORT = 18082;
const MASK_PORT = 18083;
const RECEIVER_PORT = 18787;

let failures = 0;
function check(name, ok, detail) {
  console.log((ok ? "PASS  " : "FAIL  ") + name + (detail ? "   [" + detail + "]" : ""));
  if (!ok) failures++;
}
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

function request(port, method, urlPath, body, extraHeaders) {
  return new Promise(function (resolve, reject) {
    const headers = Object.assign({ "Content-Type": "application/json" }, extraHeaders || {});
    const req = http.request({ host: "127.0.0.1", port: port, method: method, path: urlPath, headers: headers }, function (res) {
      let data = "";
      res.on("data", function (c) { data += c; });
      res.on("end", function () { resolve({ status: res.statusCode, headers: res.headers, body: data }); });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function waitFor(label, fn, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try { last = await fn(); if (last) return last; } catch (e) { last = e.message; }
    await sleep(250);
  }
  return null;
}

function makeWorkdir(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "router-smoke-" + tag + "-"));
  fs.copyFileSync(path.join(DEPLOY, "entrypoint.mjs"), path.join(dir, "entrypoint.mjs"));
  fs.copyFileSync(path.join(FIX, "stub-github.mjs"), path.join(dir, "github.mjs"));
  return dir;
}

const children = [];
function startEntrypoint(dir, maskEnabled) {
  const env = Object.assign({}, process.env, {
    PORT: String(PORT),
    APP_PORT: String(APP_PORT),
    MASK_PORT: String(MASK_PORT),
    RECEIVER_PORT: String(RECEIVER_PORT),
    APP_ENTRY: path.join(FIX, "fake-app.mjs"),
    APP_CWD: FIX,
    FAKE_APP_PORT: String(APP_PORT),
    MASK_ENABLED: maskEnabled ? "true" : "false",
    MASK_FAIL_MODE: "closed",
    MASK_PATHS: "/v1,/v1beta",
    MASKIT_BIN: path.join(FIX, "fake-maskit.mjs"),
    MASKIT_ENGINE: path.join(FIX, "fake-maskit.mjs"),
    MASKIT_DATA: path.join(dir, "maskit"),
    BACKUP_TOKEN: "smoke-token",
    FREELLMAPI_BACKUP_TOKEN: "smoke-token",
    GITHUB_TOKEN: "smoke-token",
    GITHUB_CONFIG_REPO: "stub/stub",
  });
  const child = spawn(process.execPath, [path.join(dir, "entrypoint.mjs")], { env: env, cwd: dir });
  let out = "";
  child.stdout.on("data", function (c) { out += c; });
  child.stderr.on("data", function (c) { out += c; });
  child.getLog = function () { return out; };
  children.push(child);
  return child;
}

async function stopEntrypoint(child) {
  child.kill("SIGTERM");
  await sleep(1200);
}

async function killMaskitChildren() {
  try { await request(MASK_PORT, "GET", "/__die", null); } catch (e) { /* already down */ }
  await sleep(400);
}

async function main() {
  // ── scenario 1: masking enabled ───────────────────────────────────────────
  const dir1 = makeWorkdir("on");
  const ep1 = startEntrypoint(dir1, true);

  const up = await waitFor("router", async () => {
    const r = await request(PORT, "GET", "/api/ping", null);
    return r.status === 200 ? r : null;
  }, 20000);
  check("router comes up and forwards to the app", !!up, up ? "" : String(ep1.getLog()).slice(-500));

  const SECRET_BODY = JSON.stringify({ model: "x", messages: [{ role: "user", content: "key sk-abc123DEF456 please" }] });
  const maskReady = await waitFor("maskReady", async () => {
    const r = await request(PORT, "POST", "/v1/chat/completions", SECRET_BODY);
    return r.status === 200 && r.headers["x-served-by"] === "fake-maskit" ? r : null;
  }, 20000);
  check("/v1 is routed to the masking engine once ready", !!maskReady,
    maskReady ? "served-by=" + maskReady.headers["x-served-by"] : String(ep1.getLog()).slice(-400));

  if (maskReady) {
    const parsed = JSON.parse(maskReady.body);
    check("engine rewrote the request body", String(parsed.maskedBody).indexOf("{{APIKEY_test}}") !== -1,
      String(parsed.maskedBody).slice(0, 70));
  }

  const direct = await request(PORT, "GET", "/api/ping", null);
  check("non-masked path goes straight to the app", direct.status === 200 && direct.headers["x-served-by"] === "fake-app",
    "status=" + direct.status + " served-by=" + direct.headers["x-served-by"]);

  const masked = await request(PORT, "POST", "/v1/chat/completions", SECRET_BODY,
    { "X-Forwarded-For": "203.0.113.9", "X-Forwarded-Host": "freellmapi.example.com" });
  const mBody = JSON.parse(masked.body);
  check("X-Forwarded-For is passed through unchanged", mBody.xff === "203.0.113.9", "xff=" + mBody.xff);
  check("X-Forwarded-Host is sent downstream", mBody.xfh === "freellmapi.example.com", "xfh=" + mBody.xfh);

  const noXff = await request(PORT, "GET", "/api/ping", null);
  const noXffBody = JSON.parse(noXff.body);
  check("a missing X-Forwarded-For is synthesised from the peer", noXffBody.xff === "127.0.0.1", "xff=" + noXffBody.xff);

  const setup = await request(PORT, "POST", "/api/auth/setup", JSON.stringify({ email: "x@example.com" }));
  check("public POST /api/auth/setup is blocked (403)", setup.status === 403, "status=" + setup.status);

  // ── fail-closed gate ──────────────────────────────────────────────────────
  console.log("-- killing the masking engine to exercise the gate --");
  await killMaskitChildren();
  const gated = await waitFor("gate", async () => {
    const r = await request(PORT, "POST", "/v1/chat/completions", JSON.stringify({ model: "x", messages: [] }));
    return r.status === 503 ? r : null;
  }, 15000);
  check("/v1 returns 503 while the engine is down (fail-closed)", !!gated, gated ? gated.body.slice(0, 70) : "never 503");

  const stillDirect = await request(PORT, "GET", "/api/ping", null);
  check("admin paths keep working while masking is down", stillDirect.status === 200, "status=" + stillDirect.status);

  const recovered = await waitFor("recover", async () => {
    const r = await request(PORT, "POST", "/v1/chat/completions", JSON.stringify({ model: "x", messages: [] }));
    return r.status === 200 && r.headers["x-served-by"] === "fake-maskit" ? r : null;
  }, 40000);
  check("supervisor restarts the engine and /v1 recovers", !!recovered, recovered ? "" : "no recovery within 40s");

  await stopEntrypoint(ep1);

  // ── scenario 2: masking disabled ─────────────────────────────────────────
  await killMaskitChildren();
  const dir2 = makeWorkdir("off");
  const ep2 = startEntrypoint(dir2, false);
  const up2 = await waitFor("router2", async () => {
    const r = await request(PORT, "GET", "/api/ping", null);
    return r.status === 200 ? r : null;
  }, 20000);
  check("router comes up with masking disabled", !!up2, up2 ? "" : String(ep2.getLog()).slice(-300));

  const noMask = await request(PORT, "POST", "/v1/chat/completions", JSON.stringify({ model: "x", messages: [] }));
  check("with masking off, /v1 goes straight to the app", noMask.status === 200 && noMask.headers["x-served-by"] === "fake-app",
    "served-by=" + noMask.headers["x-served-by"]);
  check("with masking off, no engine process is spawned", String(ep2.getLog()).indexOf("masking engine started") === -1);

  const setup2 = await request(PORT, "POST", "/api/auth/setup", JSON.stringify({ email: "x@example.com" }));
  check("safety block stays active with masking off", setup2.status === 403, "status=" + setup2.status);

  await stopEntrypoint(ep2);
  for (const c of children) { try { c.kill("SIGKILL"); } catch (e) { /* ignore */ } }
  await sleep(300);

  console.log("");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED");
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(function (err) {
  console.error("SMOKE TEST ERROR: " + (err && err.stack ? err.stack : err));
  process.exit(2);
});
