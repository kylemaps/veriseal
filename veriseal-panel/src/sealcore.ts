/**
 * veriseal verification core (framework-agnostic, browser WebCrypto).
 *
 * Mirrors the Python reference in src/veriseal/ byte-for-byte:
 *   - canonicalize()   <-> veriseal.canonical.canonical_json
 *   - merkleRoot()     <-> veriseal.merkle.merkle_root (RFC 6962, 0x00/0x01 domain sep)
 *   - verifySignature()<-> veriseal.signing.verify (Ed25519 over manifest sans signature/anchor)
 *
 * IMPORTANT: a Foxglove panel only ever sees *deserialized* messages, never the
 * raw serialized payload bytes that veriseal hashes into leaves. So this core
 * deliberately does NOT try to recompute leaf hashes from a live message stream.
 * What it proves in-panel:
 *   1. the manifest is authentic to its Ed25519 key (signature), and
 *   2. the listed leaf hashes fold to the signed Merkle root.
 * Whole-file byte integrity (SHA-256 of the .mcap) is the job of the CLI and the
 * standalone web verifier, which have the raw bytes. This module is honest about
 * that boundary rather than faking a proof it cannot compute.
 */

export interface SealLeaf {
  index: number;
  topic: string;
  log_time: number | bigint;
  leaf_hash: string;
}

export interface SealManifest {
  schema_version?: string;
  tool_version?: string;
  created_utc?: string;
  source: { filename: string; sha256: string; size_bytes: number };
  messages: { count: number; log_time_min: number | bigint; log_time_max: number | bigint };
  hash_alg?: string;
  merkle: { scheme?: string; root: string; ordering?: string };
  leaves: SealLeaf[];
  signature: { alg: string; public_key: string; value: string };
  anchor?: { type?: string; [k: string]: unknown } | null;
}

export interface SealCheckResult {
  ok: boolean;
  signatureOk: boolean;
  merkleOk: boolean;
  keyFingerprint: string;
  signedRoot: string;
  recomputedRoot: string;
  messageCount: number;
  logTimeMin: bigint;
  logTimeMax: bigint;
  hasAnchor: boolean;
  anchorType?: string;
  error?: string;
}

/* ---- canonical JSON: must byte-match veriseal.canonical.canonical_json ----
   Python: json.dumps(obj, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"), allow_nan=False) */
export function canonicalize(value: unknown): string {
  if (value == null) {return "null";}
  if (typeof value === "boolean") {return value ? "true" : "false";}
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {throw new Error("non-finite number");}
    return String(value);
  }
  if (typeof value === "bigint") {return value.toString();}
  if (typeof value === "string") {return JSON.stringify(value);}
  if (Array.isArray(value)) {return "[" + value.map(canonicalize).join(",") + "]";}
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  throw new Error("cannot canonicalize " + typeof value);
}

/* Large integers (log_time ns) exceed Number safety. Parse the raw JSON text
   preserving them as BigInt so canonical bytes match Python exactly. */
export function parseManifestPreservingBigInts(text: string): SealManifest {
  const tagged = text.replace(
    /:(\s*)(-?\d{16,})(\s*[,}\]])/g,
    (_m, s1: string, num: string, tail: string) => `:${s1}"__BIGINT__${num}"${tail}`,
  );
  const obj = JSON.parse(tagged) as unknown;
  const revive = (v: unknown): unknown => {
    if (typeof v === "string" && v.startsWith("__BIGINT__")) {
      return BigInt(v.slice(10));
    }
    if (Array.isArray(v)) {
      return v.map(revive);
    }
    if (v != null && typeof v === "object") {
      const o = v as Record<string, unknown>;
      for (const k of Object.keys(o)) {
        o[k] = revive(o[k]);
      }
      return o;
    }
    return v;
  };
  return revive(obj) as SealManifest;
}

/* ---- hex / base64 / PEM helpers ----
   All byte arrays are ArrayBuffer-backed (Bytes) so they satisfy WebCrypto's
   BufferSource, which excludes SharedArrayBuffer-backed views. */
type Bytes = Uint8Array<ArrayBuffer>;

function alloc(n: number): Bytes {
  return new Uint8Array(new ArrayBuffer(n));
}
function hexToBytes(hex: string): Bytes {
  const out = alloc(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToHex(buf: Bytes): string {
  let s = "";
  for (const byte of buf) {
    s += byte.toString(16).padStart(2, "0");
  }
  return s;
}
function pemToDer(pem: string): Bytes {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(body);
  const der = alloc(bin.length);
  for (let i = 0; i < bin.length; i++) {der[i] = bin.charCodeAt(i);}
  return der;
}
function utf8(s: string): Bytes {
  const enc = new TextEncoder().encode(s);
  const out = alloc(enc.length);
  out.set(enc);
  return out;
}

/* ---- SHA-256 + RFC 6962 Merkle, mirrors veriseal.merkle ---- */
async function sha256(bytes: Bytes): Promise<Bytes> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}
function concat(...arrs: Bytes[]): Bytes {
  let n = 0;
  for (const a of arrs) {n += a.length;}
  const out = alloc(n);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}
async function internalNode(left: Bytes, right: Bytes): Promise<Bytes> {
  const prefix = alloc(1);
  prefix[0] = 0x01;
  return await sha256(concat(prefix, left, right));
}
/**
 * Largest power of two strictly less than n (RFC 6962 §2.1), i.e. Python's
 * `1 << ((n - 1).bit_length() - 1)`. Exact integer math (clz32), so the split is
 * provably identical to the Python reference with no dependence on float rounding.
 * (An earlier version used `1 << Math.floor(Math.log2(n - 1))`; within the valid
 * domain, n-1 < 2^31, that never actually diverged, but exact-by-construction
 * removes any doubt and any need to reason about IEEE-754 edge cases.)
 */
function largestPow2Below(n: number): number {
  return 1 << (31 - Math.clz32(n - 1));
}
async function merkleRoot(leafHashes: Bytes[]): Promise<Bytes> {
  const n = leafHashes.length;
  if (n === 0) {return await sha256(alloc(0));}
  if (n === 1) {return leafHashes[0]!;}
  const k = largestPow2Below(n);
  const [l, r] = await Promise.all([
    merkleRoot(leafHashes.slice(0, k)),
    merkleRoot(leafHashes.slice(k)),
  ]);
  return await internalNode(l, r);
}

/** Short human fingerprint: the raw 32 Ed25519 key bytes (tail of the SPKI DER). */
export function keyFingerprint(pem: string): string {
  const der = pemToDer(pem);
  return bytesToHex(der.slice(der.length - 32));
}

async function verifySignature(manifest: SealManifest): Promise<{ ok: boolean; error?: string }> {
  const payload: Record<string, unknown> = {};
  const entries = manifest as unknown as Record<string, unknown>;
  for (const k of Object.keys(entries)) {
    if (k !== "signature" && k !== "anchor") {
      payload[k] = entries[k];
    }
  }
  const msg = utf8(canonicalize(payload));
  const sig = hexToBytes(manifest.signature.value);
  const der = pemToDer(manifest.signature.public_key);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("spki", der, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return {
      ok: false,
      error: "This runtime lacks WebCrypto Ed25519 support (needs a recent Chromium/Safari).",
    };
  }
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  return { ok };
}

function sortLeaves(leaves: readonly SealLeaf[]): SealLeaf[] {
  // sort by (log_time, topic, leaf_hash) ascending — same as seal
  return leaves.slice().sort((a, b) => {
    const at = BigInt(a.log_time);
    const bt = BigInt(b.log_time);
    if (at < bt) {return -1;}
    if (at > bt) {return 1;}
    if (a.topic < b.topic) {return -1;}
    if (a.topic > b.topic) {return 1;}
    return a.leaf_hash < b.leaf_hash ? -1 : a.leaf_hash > b.leaf_hash ? 1 : 0;
  });
}

/** Recompute the RFC 6962 Merkle root over a manifest's leaves (sorted, then hex root). */
export async function merkleRootFromLeaves(leaves: readonly SealLeaf[]): Promise<string> {
  const sorted = sortLeaves(leaves);
  const hashes = sorted.map((l) => hexToBytes(l.leaf_hash));
  return bytesToHex(await merkleRoot(hashes));
}

async function recomputeMerkleRoot(manifest: SealManifest): Promise<string> {
  return await merkleRootFromLeaves(manifest.leaves);
}

const EMPTY_RESULT: SealCheckResult = {
  ok: false,
  signatureOk: false,
  merkleOk: false,
  keyFingerprint: "",
  signedRoot: "",
  recomputedRoot: "",
  messageCount: 0,
  logTimeMin: 0n,
  logTimeMax: 0n,
  hasAnchor: false,
};

/** True when the parsed object has the fields this verifier needs. */
function isSealManifest(m: unknown): m is SealManifest {
  if (m == null || typeof m !== "object") {
    return false;
  }
  const o = m as Partial<SealManifest>;
  return (
    o.signature != null &&
    typeof o.signature.public_key === "string" &&
    typeof o.signature.value === "string" &&
    o.merkle != null &&
    typeof o.merkle.root === "string" &&
    Array.isArray(o.leaves) &&
    o.messages != null
  );
}

/**
 * Verify a parsed seal manifest's internal authenticity (signature + Merkle root).
 * Accepts untrusted parsed JSON; returns an error result if it isn't a manifest.
 */
export async function checkSeal(input: unknown): Promise<SealCheckResult> {
  if (!isSealManifest(input)) {
    return { ...EMPTY_RESULT, error: "Not a veriseal manifest (missing signature/merkle/leaves)." };
  }
  const manifest = input;

  const base: SealCheckResult = {
    ...EMPTY_RESULT,
    signedRoot: manifest.merkle.root,
    messageCount: manifest.messages.count,
    logTimeMin: BigInt(manifest.messages.log_time_min),
    logTimeMax: BigInt(manifest.messages.log_time_max),
    hasAnchor: manifest.anchor?.type != null,
    anchorType: manifest.anchor?.type,
  };

  const sig = await verifySignature(manifest);
  if (sig.error != null) {
    return { ...base, error: sig.error };
  }
  base.signatureOk = sig.ok;
  base.keyFingerprint = keyFingerprint(manifest.signature.public_key);

  base.recomputedRoot = await recomputeMerkleRoot(manifest);
  base.merkleOk = base.recomputedRoot === manifest.merkle.root;

  base.ok = base.signatureOk && base.merkleOk;
  return base;
}

/** Cross-check what Foxglove has loaded against what the seal covers. */
export interface LoadedShape {
  topics: Set<string>;
  messageCount?: number;
}
export interface ShapeMismatch {
  extraTopics: string[]; // topics loaded but not in the seal's leaves
}
export function crossCheckShape(manifest: SealManifest, loaded: LoadedShape): ShapeMismatch {
  const sealedTopics = new Set(manifest.leaves.map((l) => l.topic));
  const extraTopics: string[] = [];
  for (const t of loaded.topics) {
    if (!sealedTopics.has(t)) {extraTopics.push(t);}
  }
  return { extraTopics: extraTopics.sort() };
}
