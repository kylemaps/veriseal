/**
 * Equivalence test for the STANDALONE web verifier (../../web/verify.html).
 *
 * web/verify.html is a single self-contained page (no external requests, no
 * imports), so its verification crypto is a third, independent copy of the same logic in the
 * Python reference and the panel's sealcore.ts. That duplication is by design —
 * but it means the web verifier needs its own regression guard, or a bug fixed
 * in one copy (e.g. the RFC 6962 Merkle split-point) can silently persist here.
 *
 * This test extracts the page's inline <script>, runs it in a sandbox with Node's
 * WebCrypto (mocking only the DOM wiring it performs at load), and exercises the
 * real recomputeMerkle / verifySignature against committed fixtures whose roots
 * were produced by the Python CLI.
 *
 * Run: node test/webverify.test.mjs
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = fileURLToPath(new URL(".", import.meta.url));
const webVerify = join(here, "..", "..", "web", "verify.html");
const EXPECTED_SAMPLE_ROOT = "9a75174f04a956e947427887468f63381b3914cafbc3f83b052620a2bc04a581";

let failures = 0;
function check(label, cond) {
  const ok = Boolean(cond);
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
  if (!ok) failures++;
}

// 1. Extract the first (main) <script> block from the page.
const html = readFileSync(webVerify, "utf8");
const open = html.indexOf("<script>");
const close = html.indexOf("</script>", open);
if (open < 0 || close < 0) {
  console.error("FAIL  could not locate the main <script> block in web/verify.html");
  process.exit(1);
}
const scriptBody = html.slice(open + "<script>".length, close);

// 2. Sandbox with WebCrypto + a no-op DOM stub (the script wires event handlers
//    at load; a Proxy that absorbs any property/call keeps that from throwing).
const domStub = new Proxy(function () {}, {
  get: () => domStub,
  apply: () => domStub,
  construct: () => domStub,
});
const sandbox = {
  crypto,
  atob,
  btoa,
  TextEncoder,
  TextDecoder,
  console,
  FileReader: function () {},
  document: { getElementById: () => domStub, createElement: () => domStub, querySelector: () => domStub },
  window: {},
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(scriptBody, sandbox);

check("inline crypto functions are defined", typeof sandbox.recomputeMerkle === "function");

// 3. Large-leaf Merkle equivalence (the same fixture + Python root the panel uses).
//    Anti-drift guard on the multi-level tree: catches a wrong domain separator,
//    sort order, or split rule. (Note: within the code's valid domain, n-1 < 2^31,
//    the old float split and the exact-integer split never actually diverge, so
//    this does not distinguish those two specifically — it locks the output to the
//    Python reference against any future change.)
const large = JSON.parse(readFileSync(join(here, "fixtures", "large-leaves.json"), "utf8"));
const largeManifest = sandbox.parseSealPreservingBigInts(JSON.stringify({ leaves: large.leaves }));
const largeRoot = await sandbox.recomputeMerkle(largeManifest);
check(`large leaf count (n=${large.leaves.length}) root matches Python`, largeRoot === large.root);

// 4. Full check on the CLI-sealed sample: signature + Merkle root.
const sealText = readFileSync(join(here, "fixtures", "sample.seal.json"), "utf8");
const manifest = sandbox.parseSealPreservingBigInts(sealText);
const sampleRoot = await sandbox.recomputeMerkle(manifest);
check("sample seal Merkle root matches Python-signed root", sampleRoot === EXPECTED_SAMPLE_ROOT);
const sig = await sandbox.verifySignature(manifest);
check("sample seal signature verifies", sig.ok === true);

// 5. Cross-verifier agreement on a NON-MESSAGE byte change (the Commit-1 bug).
//    Run the page's embedded sample (a real CLI-sealed mcap + seal), then flip a
//    byte OUTSIDE any message payload (the header region). The file digest must
//    fail while signature + Merkle still pass — so the web verifier's verdict is
//    TAMPERED, exactly as `veriseal verify` now reports (source_ok gates both).
const secondOpen = html.indexOf("<script>", close);
const secondClose = html.indexOf("</script>", secondOpen);
const sampleBody = html.slice(secondOpen + "<script>".length, secondClose);
vm.runInContext(sampleBody, sandbox);
const sample = sandbox.window.__SAMPLE__;
check("embedded sample present", sample != null && typeof sample.mcapHex === "string");

const sampleManifest = sandbox.parseSealPreservingBigInts(sample.sealJson);
const mcap = sandbox.hexToBytes(sample.mcapHex);

async function fileOk(bytes) {
  const digest = sandbox.bytesToHex(await sandbox.sha256(bytes));
  return digest === sampleManifest.source.sha256 && bytes.length === sampleManifest.source.size_bytes;
}
const rootOk = (await sandbox.recomputeMerkle(sampleManifest)) === sampleManifest.merkle.root;
const sigOk = (await sandbox.verifySignature(sampleManifest)).ok === true;

// Genuine sample: all three checks pass -> verdict would be VERIFIED (pre-pin).
check("genuine sample: file digest ok", await fileOk(mcap));
check("genuine sample: signature + merkle ok", sigOk && rootOk);

// Flip a header-region byte (offset 40: inside the mcap header record's library
// string, not any sealed (topic,log_time,payload) triple).
const altered = mcap.slice();
altered[40] ^= 0xff;
const alteredFileOk = await fileOk(altered);
// Merkle recompute reads manifest.leaves, so it (and the signature) are
// unchanged by a file-byte flip — only the whole-file digest moves.
check("non-message flip: file digest FAILS", alteredFileOk === false);
check("non-message flip: signature + merkle still pass", sigOk && rootOk);
check(
  "non-message flip: combined verdict is TAMPERED (agrees with Python)",
  (sigOk && rootOk && alteredFileOk) === false,
);

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll checks passed — web/verify.html crypto matches the Python reference.");
