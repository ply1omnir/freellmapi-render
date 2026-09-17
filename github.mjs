// github.mjs — GitHub Releases helper for config snapshots.
//
// Responsibilities are intentionally narrow: list / download / create releases
// and assets in the single private config repository named by GITHUB_CONFIG_REPO.
// The token comes from the environment (Render secret), never from the repo.

const API = "https://api.github.com";
const UPLOADS = "https://uploads.github.com";
const UA = "omniroute-render-supervisor";

export function requiredToken() {
  const t = process.env.GITHUB_TOKEN;
  if (!t || !t.trim()) throw new Error("GITHUB_TOKEN is not configured");
  return t.trim();
}

export function configRepo() {
  const r = process.env.GITHUB_CONFIG_REPO;
  if (!r || !r.trim()) throw new Error("GITHUB_CONFIG_REPO is not configured");
  return r.trim();
}

const REQUEST_TIMEOUT_MS = 60000;

export async function gh(path, options) {
  const opts = options || {};
  const headers = Object.assign(
    {
      Authorization: "Bearer " + requiredToken(),
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": UA,
    },
    opts.headers || {}
  );
  // Node's fetch has NO default timeout. Without this a stalled connection to
  // GitHub hangs the caller forever — measured as a manual snapshot that never
  // returned a response at all.
  const signal = opts.signal || AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  const res = await fetch(API + path, Object.assign({}, opts, { headers: headers, signal: signal }));
  return res;
}

function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

async function ghJson(path, options) {
  const res = await gh(path, options);
  const text = await res.text();
  if (!res.ok) {
    throw new Error("GitHub " + path + " -> " + res.status + " " + text.slice(0, 300));
  }
  return text ? JSON.parse(text) : null;
}

export const MANUAL_PREFIX = "snap-manual-";
export const AUTO_PREFIX = "snap-auto-";

/** List every snapshot release, newest first. */
export async function listSnapshots() {
  const repo = configRepo();
  const out = [];
  for (let page = 1; page <= 5; page++) {
    const batch = await ghJson(
      "/repos/" + repo + "/releases?per_page=100&page=" + page
    );
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const rel of batch) {
      if (typeof rel.tag_name !== "string") continue;
      if (
        !rel.tag_name.startsWith(MANUAL_PREFIX) &&
        !rel.tag_name.startsWith(AUTO_PREFIX)
      ) {
        continue;
      }
      out.push({
        id: rel.id,
        tag: rel.tag_name,
        createdAt: rel.created_at,
        manual: rel.tag_name.startsWith(MANUAL_PREFIX),
        assets: (rel.assets || []).map(function (a) {
          return { id: a.id, name: a.name, size: a.size };
        }),
      });
    }
    if (batch.length < 100) break;
  }
  // Sort by the timestamp embedded in OUR tag, never by GitHub's created_at:
  // releases created in quick succession can share (or misreport) created_at,
  // and picking the wrong one silently restores a stale configuration.
  out.sort(function (a, b) {
    const da = tagToDate(a.tag);
    const db = tagToDate(b.tag);
    if (da && db && da.getTime() !== db.getTime()) return db.getTime() - da.getTime();
    return String(b.tag).localeCompare(String(a.tag));
  });
  return out;
}

/** Newest snapshot that actually carries an asset. */
export async function latestSnapshot() {
  const all = await listSnapshots();
  for (const rel of all) {
    if (rel.assets.length > 0) return rel;
  }
  return null;
}

/** Download a release asset as a Buffer. */
export async function downloadAsset(assetId) {
  const repo = configRepo();
  const res = await gh("/repos/" + repo + "/releases/assets/" + assetId, {
    headers: { Accept: "application/octet-stream" },
    signal: AbortSignal.timeout(120000),
  });
  if (!res.ok) {
    throw new Error("asset " + assetId + " download failed: " + res.status);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  return buf;
}

/** Create a release and upload one gzip asset. Returns {tag, assetId, size}. */
export async function publishSnapshot(tag, bodyText, gzBuffer, assetName) {
  const repo = configRepo();
  const release = await ghJson("/repos/" + repo + "/releases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      tag_name: tag,
      name: tag,
      body: bodyText,
      draft: false,
      prerelease: false,
    }),
  });
  const url =
    UPLOADS +
    "/repos/" +
    repo +
    "/releases/" +
    release.id +
    "/assets?name=" +
    encodeURIComponent(assetName);

  // The upload host has been observed returning transient 5xx
  // ("Error creating asset temp dir"). Retry, and if it still fails, delete the
  // release we just created so we never leave asset-less releases behind.
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: "Bearer " + requiredToken(),
          "Content-Type": "application/gzip",
          "User-Agent": UA,
        },
        body: gzBuffer,
        signal: AbortSignal.timeout(120000),
      });
      const text = await res.text();
      if (!res.ok) {
        lastError = "asset upload failed: " + res.status + " " + text.slice(0, 200);
      } else {
        const asset = JSON.parse(text);
        return { tag: tag, releaseId: release.id, assetId: asset.id, size: gzBuffer.length, attempts: attempt };
      }
    } catch (err) {
      lastError = "asset upload threw: " + (err && err.message ? err.message : String(err));
    }
    if (attempt < 3) await sleep(attempt * 3000);
  }

  try {
    await deleteRelease(release.id);
  } catch (e) {
    // best effort
  }
  throw new Error(lastError || "asset upload failed");
}

/** Delete a release together with its assets. */
export async function deleteRelease(releaseId) {
  const repo = configRepo();
  const res = await gh("/repos/" + repo + "/releases/" + releaseId, {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 404) {
    throw new Error("release delete failed: " + res.status);
  }
  return true;
}

export function tsTag(prefix, date) {
  const d = date || new Date();
  const p = function (n, w) {
    const s = String(n);
    return "0".repeat(Math.max(0, w - s.length)) + s;
  };
  return (
    prefix +
    d.getUTCFullYear() +
    p(d.getUTCMonth() + 1, 2) +
    p(d.getUTCDate(), 2) +
    "-" +
    p(d.getUTCHours(), 2) +
    p(d.getUTCMinutes(), 2) +
    p(d.getUTCSeconds(), 2)
  );
}

export function tagToDate(tag) {
  const m = /(\d{8})-(\d{6})$/.exec(tag);
  if (!m) return null;
  const d = m[1];
  const t = m[2];
  return new Date(
    Date.UTC(
      Number(d.slice(0, 4)),
      Number(d.slice(4, 6)) - 1,
      Number(d.slice(6, 8)),
      Number(t.slice(0, 2)),
      Number(t.slice(2, 4)),
      Number(t.slice(4, 6))
    )
  );
}
