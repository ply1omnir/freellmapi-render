// Test double for ./github.mjs — no network, "first boot" (no snapshots).
export function configRepo() { return "stub/stub"; }
export function requiredToken() { return "stub-token"; }
export async function listSnapshots() { return []; }
export async function latestSnapshot() { return null; }
export async function downloadAsset() { return Buffer.from(""); }
export async function publishSnapshot() { return { assetId: 1 }; }
export async function deleteRelease() { return {}; }
export function tagToDate() { return null; }
export function tsTag(prefix) { return prefix + "stub"; }
