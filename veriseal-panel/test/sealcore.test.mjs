/**
 * Equivalence + tamper test for the panel's verification core.
 *
 * Compiles src/sealcore.ts with tsc, then runs it (Node's WebCrypto) against a
 * committed manifest that was sealed by the Python `veriseal` CLI. Asserts:
 *   - the genuine manifest verifies (signature + Merkle root), and the recomputed
 *     root equals the root the Python tool signed (byte-for-byte equivalence);
 *   - a flipped leaf hash fails both Merkle and signature checks;
 *   - an altered signed field fails the signature check;
 *   - a non-manifest input is rejected.
 *
 * Run: node test/sealcore.test.mjs   (needs the dev dependencies installed)
 */
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");

// The root Merkle root the Python veriseal CLI produced for this fixture.
const EXPECTED_ROOT = "9a75174f04a956e947427887468f63381b3914cafbc3f83b052620a2bc04a581";

let failures = 0;
function check(label, cond) {
  const ok = Boolean(cond);
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
  if (!ok) failures++;
}

// 1. Compile sealcore.ts to an ESM module we can import.
const out = mkdtempSync(join(tmpdir(), "sealcore-"));
const tsconfig = join(out, "tsconfig.json");
writeFileSync(
  tsconfig,
  JSON.stringify({
    compilerOptions: {
      target: "ES2022",
      module: "ES2022",
      moduleResolution: "bundler",
      lib: ["ES2022", "DOM"],
      strict: true,
      skipLibCheck: true,
      outDir: out,
    },
    include: [join(root, "src/sealcore.ts")],
  }),
);
execSync(`npx tsc -p "${tsconfig}"`, { cwd: root, stdio: "inherit" });

const { checkSeal, parseManifestPreservingBigInts, crossCheckShape } = await import(
  "file://" + join(out, "sealcore.js").replace(/\\/g, "/")
);

const sealText = readFileSync(join(here, "fixtures/sample.seal.json"), "utf8");

// 2. Genuine manifest.
const manifest = parseManifestPreservingBigInts(sealText);
const genuine = await checkSeal(manifest);
check("genuine manifest verifies (ok)", genuine.ok);
check("  signature valid", genuine.signatureOk);
check("  merkle valid", genuine.merkleOk);
check("  recomputed root matches the Python-signed root", genuine.recomputedRoot === EXPECTED_ROOT);
check("  signed root == recomputed root", genuine.signedRoot === genuine.recomputedRoot);

// 3. Flipped leaf hash.
const flipped = parseManifestPreservingBigInts(sealText);
flipped.leaves[3].leaf_hash = "00".repeat(32);
const flippedRes = await checkSeal(flipped);
check("flipped leaf hash -> not ok", !flippedRes.ok);
check("  merkle fails", !flippedRes.merkleOk);
check("  signature fails (covers leaves)", !flippedRes.signatureOk);

// 4. Altered signed field.
const altered = parseManifestPreservingBigInts(sealText);
altered.messages.count = 999;
const alteredRes = await checkSeal(altered);
check("altered messages.count -> signature fails", !alteredRes.signatureOk && !alteredRes.ok);

// 5. Not a manifest.
const bad = await checkSeal({ foo: 1 });
check("non-manifest input rejected", !bad.ok && typeof bad.error === "string");

// 6. Coverage cross-check.
const shape = crossCheckShape(manifest, { topics: new Set(["/pose", "/status", "/extra"]) });
check("crossCheckShape flags unsealed topic", shape.extraTopics.join(",") === "/extra");

rmSync(out, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll checks passed — panel core matches the Python reference.");
