import { Immutable, PanelExtensionContext, Topic } from "@foxglove/extension";
import { ReactElement, useCallback, useEffect, useLayoutEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";

import {
  checkSeal,
  crossCheckShape,
  parseManifestPreservingBigInts,
  SealCheckResult,
  SealManifest,
} from "./sealcore";

type Verdict = "idle" | "verified" | "tampered" | "error";

const palette = {
  bg: "#0e1116",
  panel: "#161b22",
  panel2: "#1c222b",
  ink: "#e7ecf2",
  ink2: "#a4afbd",
  ink3: "#6f7b8a",
  line: "#262d38",
  lineStrong: "#333c48",
  accent: "#58a6d8",
  ok: "#35c98a",
  okBg: "#10261e",
  bad: "#f0555a",
  badBg: "#2a1417",
  warn: "#e0a13c",
  warnBg: "#291f10",
  mono: 'ui-monospace, "Cascadia Code", "SF Mono", Menlo, Consolas, monospace',
};

function fmtTime(ns: bigint): string {
  if (ns === 0n) {return "—";}
  const ms = Number(ns / 1_000_000n);
  try {
    return new Date(ms).toISOString().replace("T", " ").replace(".000Z", "Z");
  } catch {
    return ns.toString();
  }
}

function short(hex: string): string {
  if (hex.length <= 34) {return hex;}
  return hex.slice(0, 24) + "…" + hex.slice(-8);
}

function SealCheckPanel({ context }: { context: PanelExtensionContext }): ReactElement {
  const [topics, setTopics] = useState<undefined | Immutable<Topic[]>>();
  const [renderDone, setRenderDone] = useState<(() => void) | undefined>();

  const [manifest, setManifest] = useState<SealManifest | undefined>();
  const [manifestName, setManifestName] = useState<string | undefined>();
  const [result, setResult] = useState<SealCheckResult | undefined>();
  const [parseError, setParseError] = useState<string | undefined>();

  useLayoutEffect(() => {
    context.onRender = (renderState, done) => {
      setRenderDone(() => done);
      setTopics(renderState.topics);
    };
    context.watch("topics");
  }, [context]);

  useEffect(() => {
    renderDone?.();
  }, [renderDone]);

  const loadManifestText = useCallback(async (text: string, name: string) => {
    setParseError(undefined);
    setResult(undefined);
    let parsed: SealManifest;
    try {
      parsed = parseManifestPreservingBigInts(text);
    } catch {
      setManifest(undefined);
      setManifestName(name);
      setParseError("That file is not valid JSON.");
      return;
    }
    setManifest(parsed);
    setManifestName(name);
    const res = await checkSeal(parsed);
    setResult(res);
  }, []);

  const onFile = useCallback(
    (file: File | undefined) => {
      if (file == null) {return;}
      const reader = new FileReader();
      reader.onload = () => {
        // readAsText always yields a string result
        const text = typeof reader.result === "string" ? reader.result : "";
        void loadManifestText(text, file.name);
      };
      reader.readAsText(file);
    },
    [loadManifestText],
  );

  const loadedTopics = useMemo(() => new Set((topics ?? []).map((t) => t.name)), [topics]);

  const shape = useMemo(() => {
    if (!manifest) {return undefined;}
    return crossCheckShape(manifest, { topics: loadedTopics });
  }, [manifest, loadedTopics]);

  const verdict: Verdict =
    manifest == null
      ? "idle"
      : parseError != null || result?.error != null
        ? "error"
        : result?.ok === true
          ? "verified"
          : "tampered";

  const accent =
    verdict === "verified"
      ? palette.ok
      : verdict === "tampered"
        ? palette.bad
        : verdict === "error"
          ? palette.warn
          : palette.ink3;
  const accentBg =
    verdict === "verified"
      ? palette.okBg
      : verdict === "tampered"
        ? palette.badBg
        : verdict === "error"
          ? palette.warnBg
          : palette.panel;

  return (
    <div
      style={{
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
        color: palette.ink,
        background: palette.bg,
        height: "100%",
        overflowY: "auto",
        padding: "14px 16px 20px",
        boxSizing: "border-box",
        fontSize: 13,
        lineHeight: 1.5,
      }}
    >
      {/* header */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 12 }}>
        <span style={{ fontFamily: palette.mono, fontWeight: 600, fontSize: 15 }}>
          veri<span style={{ color: palette.accent }}>seal</span>
        </span>
        <span
          style={{
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: "0.09em",
            color: palette.ink3,
            border: `1px solid ${palette.lineStrong}`,
            padding: "2px 6px",
            borderRadius: 20,
          }}
        >
          seal check
        </span>
      </div>

      {/* verdict badge */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 14,
          padding: "16px 16px",
          borderRadius: 10,
          background: accentBg,
          border: `1px solid ${palette.line}`,
          transition: "background .2s",
        }}
      >
        <div
          style={{
            flex: "none",
            width: 44,
            height: 44,
            borderRadius: "50%",
            display: "grid",
            placeItems: "center",
            fontSize: 22,
            fontWeight: 700,
            color: accent,
            border: `2px solid ${accent}`,
          }}
        >
          {verdict === "verified"
            ? "✓"
            : verdict === "tampered"
              ? "✗"
              : verdict === "error"
                ? "!"
                : "·"}
        </div>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: accent, letterSpacing: "-0.01em" }}>
            {verdict === "verified"
              ? "MANIFEST AUTHENTIC"
              : verdict === "tampered"
                ? "MANIFEST INVALID"
                : verdict === "error"
                  ? "CANNOT CHECK"
                  : "No seal loaded"}
          </div>
          <div style={{ fontSize: 12.5, color: palette.ink2, marginTop: 2 }}>
            {verdict === "verified" && result
              ? `Signature valid, internally consistent · key ${result.keyFingerprint.slice(0, 16)}… · raw file not checked in-panel`
              : verdict === "tampered"
                ? "The manifest is not internally consistent — see below."
                : verdict === "error"
                  ? (parseError ?? result?.error)
                  : "Load the log's .seal.json to check it in-workflow."}
          </div>
        </div>
      </div>

      {/* file loader */}
      <label
        style={{
          display: "block",
          marginTop: 12,
          padding: "10px 12px",
          borderRadius: 8,
          border: `1.5px dashed ${palette.lineStrong}`,
          background: palette.panel,
          cursor: "pointer",
          fontSize: 12.5,
          color: palette.ink2,
        }}
      >
        {manifestName ? (
          <span style={{ fontFamily: palette.mono, color: palette.ink }}>{manifestName}</span>
        ) : (
          "Choose the .seal.json manifest…"
        )}
        <input
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={(e) => { onFile(e.target.files?.[0]); }}
        />
      </label>

      {/* checks */}
      {result != null && result.error == null && (
        <div style={{ marginTop: 14, display: "grid", gap: 0 }}>
          <CheckRow
            pass={result.signatureOk}
            name="Manifest signature"
            desc={
              result.signatureOk
                ? "Authentic to its Ed25519 key."
                : "Signature INVALID — the manifest was altered."
            }
            kvs={[
              ["key", short(result.keyFingerprint)],
              ["alg", "Ed25519"],
            ]}
          />
          <CheckRow
            pass={result.merkleOk}
            name="Merkle root"
            desc={
              result.merkleOk
                ? "Listed message hashes fold to the signed root."
                : "Message hashes do not fold to the signed root."
            }
            kvs={[
              ["signed", short(result.signedRoot)],
              ["computed", short(result.recomputedRoot), result.merkleOk ? "good" : "bad"],
            ]}
          />
          <CheckRow
            kind="info"
            name="Sealed window"
            desc="The provenance recorded in the seal."
            kvs={[
              ["messages", String(result.messageCount)],
              ["from", fmtTime(result.logTimeMin)],
              ["to", fmtTime(result.logTimeMax)],
              ["anchor", result.hasAnchor ? (result.anchorType ?? "yes") : "none"],
            ]}
          />
          {shape != null && shape.extraTopics.length > 0 && (
            <CheckRow
              kind="warn"
              name="Coverage mismatch"
              desc="This view shows topics the seal does not cover. The seal only vouches for the sealed messages."
              kvs={shape.extraTopics.slice(0, 6).map((t): [string, string] => ["not sealed", t])}
            />
          )}
        </div>
      )}

      {/* honesty note */}
      <div
        style={{
          marginTop: 16,
          paddingTop: 12,
          borderTop: `1px solid ${palette.line}`,
          fontSize: 11.5,
          color: palette.ink3,
        }}
      >
        This panel verifies the seal&rsquo;s <b style={{ color: palette.ink2 }}>signature</b> and{" "}
        <b style={{ color: palette.ink2 }}>Merkle root</b> — that the manifest is authentic to its
        signer. Whole-file byte integrity (the SHA-256 of the .mcap) needs the raw file, which a
        panel never sees; run <code style={{ fontFamily: palette.mono }}>veriseal verify</code> or
        the standalone web verifier for that.
      </div>
    </div>
  );
}

function CheckRow({
  pass,
  kind,
  name,
  desc,
  kvs,
}: {
  pass?: boolean;
  kind?: "info" | "warn";
  name: string;
  desc: string;
  kvs: Array<[string, string] | [string, string, "good" | "bad"]>;
}): ReactElement {
  const mark = kind === "info" ? "◉" : kind === "warn" ? "△" : pass === true ? "✓" : "✗";
  const color =
    kind === "info"
      ? palette.accent
      : kind === "warn"
        ? palette.warn
        : pass === true
          ? palette.ok
          : palette.bad;
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "20px 1fr",
        gap: 10,
        padding: "11px 0",
        borderBottom: `1px solid ${palette.line}`,
      }}
    >
      <span style={{ color, fontSize: 14 }}>{mark}</span>
      <div>
        <div style={{ fontWeight: 600, fontSize: 13 }}>{name}</div>
        <div style={{ fontSize: 12, color: palette.ink2, marginTop: 1 }}>{desc}</div>
        {kvs.length > 0 && (
          <div
            style={{
              fontFamily: palette.mono,
              fontSize: 11.5,
              marginTop: 5,
              display: "grid",
              gap: 1,
              overflowX: "auto",
            }}
          >
            {kvs.map(([k, v, tone], i) => (
              <div key={i} style={{ whiteSpace: "nowrap" }}>
                <span style={{ color: palette.ink3, display: "inline-block", minWidth: 78 }}>
                  {k}
                </span>
                <span
                  style={{
                    color:
                      tone === "good" ? palette.ok : tone === "bad" ? palette.bad : palette.ink2,
                  }}
                >
                  {v}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function initSealCheckPanel(context: PanelExtensionContext): () => void {
  const root = createRoot(context.panelElement);
  root.render(<SealCheckPanel context={context} />);
  return () => {
    root.unmount();
  };
}
