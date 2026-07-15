"""veriseal pack — build a portable incident-evidence bundle from a sealed MCAP.

The bundle lets a recipient (court, insurer, regulator) independently re-verify a
sealed log without trusting the operator or veriseal: the manifest, a human-readable
report, the OpenTimestamps proof, and a fully offline copy of the standalone web
verifier are all included. This module renders the SAME `VerificationResult` that
`veriseal verify` computes (see `veriseal.verify.run_verification`) — it does not
recompute integrity checks on its own.

Every claim in the generated report is scoped to what the crypto actually proves:
integrity-since-sealing and authenticity-to-a-key. It never asserts the log's
CONTENTS are true (a compromised recorder can still sign false data), and it never
claims the bundle "satisfies" or "complies with" any regulation — only that it
supports a disclosure obligation by providing tamper-evident, independently
verifiable logs.
"""

from __future__ import annotations

import base64
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from veriseal.canonical import canonical_json
from veriseal.verify import VerificationResult, run_verification

_WEB_VERIFIER = Path(__file__).resolve().parent.parent.parent / "web" / "verify.html"


@dataclass
class PackResult:
    out_dir: Path
    ok: bool
    result: VerificationResult


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ns_to_iso(ns: int) -> str:
    return _iso(datetime.fromtimestamp(ns / 1_000_000_000, tz=UTC))


def _topic_counts(manifest: dict) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for leaf in manifest["leaves"]:
        counts[leaf["topic"]] = counts.get(leaf["topic"], 0) + 1
    return sorted(counts.items())


def _anchor_report_lines(result: VerificationResult) -> list[str]:
    a = result.anchor
    manifest_anchor = result.manifest.get("anchor")
    if not a.present or manifest_anchor is None:
        return [
            "Timestamp anchor: NONE",
            "  This manifest was sealed with --no-anchor, or anchoring failed at seal time.",
            "  The sealed time (created_utc) rests only on the sealer's assertion — it is",
            "  not independently corroborated.",
        ]
    lines = ["Timestamp anchor: OpenTimestamps (Bitcoin)"]
    if a.error is not None:
        lines.append(f"  Anchor proof ERROR: {a.error}")
        lines.append("  Anchor status could not be determined; treat the sealed time as")
        lines.append("  asserted, not proven.")
    elif a.commits_ok is False:
        lines.append("  Anchor proof INVALID: does not commit to this manifest.")
        lines.append("  Do not treat the sealed time as proven; treat it as asserted only.")
    elif a.status == "confirmed":
        lines.append(f"  Status: CONFIRMED in Bitcoin block #{a.block_height}")
        lines.append(
            "  A Bitcoin block header attests that the sealed Merkle root existed no later"
        )
        lines.append("  than that block's timestamp. This is an independent, public timestamp.")
    else:
        lines.append("  Status: PENDING attestation (not yet confirmed in a Bitcoin block)")
        lines.append(
            "  A calendar server has acknowledged the submission, but no Bitcoin block has"
        )
        lines.append(
            "  yet included it. Do not describe this log as 'anchored' or 'Bitcoin-timestamped'"
        )
        lines.append("  until the status above reads CONFIRMED — re-run `veriseal verify` later,")
        lines.append("  or `veriseal pack` again, to check for confirmation.")
    submitted = manifest_anchor.get("submitted_utc")
    if submitted:
        lines.append(f"  Submitted: {submitted}")
    return lines


def _build_report(result: VerificationResult, generated_at: datetime) -> str:
    """Human-readable verification report. Deterministic given the same manifest
    and MCAP, EXCEPT the 'Report generated' line, which is explicitly labelled
    and excluded from any hash or signature — it is not part of the evidence."""
    m = result.manifest
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("VERISEAL INCIDENT EVIDENCE — VERIFICATION REPORT")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Report generated: {_iso(generated_at)}  (not part of the sealed evidence)")
    lines.append("")
    lines.append("-" * 72)
    lines.append("VERDICT")
    lines.append("-" * 72)
    if result.ok:
        lines.append("INTACT — signature valid, Merkle root matches, source file unchanged.")
    else:
        lines.append("TAMPERED / INCOMPLETE — see failing checks below.")
    lines.append("")
    lines.append("-" * 72)
    lines.append("CHECKS")
    lines.append("-" * 72)
    sig_status = "PASS" if result.sig_ok else "FAIL"
    root_status = "PASS" if result.root_ok else "FAIL"
    source_status = "PASS" if result.source_ok else "FAIL"
    lines.append(f"[{sig_status}] Manifest signature (Ed25519)")
    lines.append(f"[{root_status}] Merkle root (RFC 6962-SHA256)")
    lines.append(f"[{source_status}] Source file digest (SHA-256, byte-exact)")
    if result.pubkey_pinned:
        pubkey_status = "PASS" if result.pubkey_ok else "FAIL"
        lines.append(f"[{pubkey_status}] Signer key pinned to caller-supplied --pubkey")
    else:
        lines.append("[N/A ] Signer key was NOT pinned against an out-of-band key for this report.")
        lines.append("       The key below is only what the manifest itself claims.")
    if result.modifications or result.removals or result.additions:
        lines.append("")
        lines.append("Tamper localisation:")
        for topic, log_time in result.modifications:
            lines.append(f"  MODIFIED  topic={topic!r} log_time={log_time}")
        for topic, log_time in result.removals:
            lines.append(f"  REMOVED   topic={topic!r} log_time={log_time}")
        for topic, log_time in result.additions:
            lines.append(f"  ADDED     topic={topic!r} log_time={log_time}")
    lines.append("")
    lines.append("-" * 72)
    lines.append("SEALED LOG")
    lines.append("-" * 72)
    lines.append(f"Filename:        {m['source']['filename']}")
    lines.append(f"SHA-256:         {m['source']['sha256']}")
    lines.append(f"Size:            {m['source']['size_bytes']} bytes")
    lines.append(f"Messages sealed: {m['messages']['count']}")
    lines.append(f"Time window:     {_ns_to_iso(m['messages']['log_time_min'])}")
    lines.append(f"              -> {_ns_to_iso(m['messages']['log_time_max'])}")
    lines.append(f"Sealed at:       {m.get('created_utc', 'unknown')}")
    lines.append(f"Merkle root:     {m['merkle']['root']}")
    lines.append("Topics covered:")
    for topic, count in _topic_counts(m):
        lines.append(f"  {topic}  ({count} messages)")
    lines.append("")
    lines.append("-" * 72)
    lines.append("SIGNER")
    lines.append("-" * 72)
    lines.append(f"Algorithm:  {m['signature']['alg']}")
    lines.append("Public key:")
    for pline in m["signature"]["public_key"].strip().splitlines():
        lines.append(f"  {pline}")
    lines.append("")
    lines.append(
        "This report does NOT establish that the key above belongs to a specific"
    )
    lines.append(
        "organization or individual. Key identity must be established out-of-band"
    )
    lines.append(
        "(e.g. by comparing against a key fingerprint published or provided separately"
    )
    lines.append("by the sealing party) and pinned with `veriseal verify --pubkey`.")
    lines.append("")
    lines.append("-" * 72)
    lines.append("ANCHOR")
    lines.append("-" * 72)
    lines.extend(_anchor_report_lines(result))
    lines.append("")
    lines.append("-" * 72)
    lines.append("HOW TO RE-VERIFY THIS YOURSELF")
    lines.append("-" * 72)
    lines.append("You do not need to trust this report, the sealing party, or veriseal.")
    lines.append("")
    lines.append("Option A — offline, in a browser, no install:")
    lines.append("  Open verify.html (included in this bundle) and drop in the .mcap")
    lines.append("  log and manifest.seal.json. It recomputes the signature, Merkle root,")
    lines.append("  and file digest entirely client-side — no network calls.")
    lines.append("")
    lines.append("Option B — veriseal CLI:")
    lines.append("  pip install git+https://github.com/kylemaps/veriseal")
    lines.append("  veriseal verify <log.mcap> manifest.seal.json --pubkey <signer's pinned key>")
    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines) + "\n"


_COVER_SHEET = """\
VERISEAL INCIDENT EVIDENCE BUNDLE — COVER SHEET
================================================

WHAT THIS BUNDLE IS
--------------------
A tamper-evident evidence package for one sealed robot/autonomy log. It contains
the signed manifest, a human-readable verification report, the timestamp proof
(if any), and a fully offline, independent verifier — so a recipient who trusts
neither the operator nor veriseal can check the evidence themselves.

WHAT THE SEAL PROVES
---------------------
  1. INTEGRITY SINCE SEALING — the log file has not changed, byte-for-byte,
     since it was sealed (SHA-256 file digest + RFC 6962 Merkle tree over every
     message).
  2. AUTHENTICITY TO A KEY — the manifest was produced by whoever holds the
     Ed25519 private key named in this bundle (digital signature).
  3. (If an anchor is present and CONFIRMED) INDEPENDENT TIMESTAMP — a public
     Bitcoin block attests the sealed content existed no later than that block.

WHAT THE SEAL DOES NOT PROVE
------------------------------
  - That the log's CONTENTS are a truthful record of what happened. A recorder
    that is compromised, misconfigured, or dishonest at capture time can sign
    false data; the seal only proves the data has not changed SINCE it was
    signed, not that it was true when signed. Integrity is not veracity.
  - That the named key belongs to any specific organization or person. Key
    identity requires an out-of-band check — see the verification report.
  - Anything about a log sealed without a --pubkey pin having been checked
    against a key the recipient independently trusts. Pin the key you were
    given out-of-band, not merely the key embedded in the manifest.

HOW THIS RELATES TO EU REGULATION
-----------------------------------
This bundle is evidence infrastructure, not a compliance certificate. It DOES
NOT itself satisfy, or certify compliance with, any regulation. What it does:
provides tamper-evident, independently re-verifiable logs that a manufacturer
can use IN SUPPORT OF disclosure and incident-reporting obligations, including:

  - EU Product Liability Directive (2024/2853) — Article 9's disclosure duty:
    a court may order a manufacturer to disclose relevant evidence, and a
    manufacturer's own, unverifiable logs are inherently self-serving. A
    tamper-evident, independently verifiable log is stronger evidence of
    what a system did.
  - EU AI Act (Regulation 2024/1689), Article 73 — serious-incident reporting
    to market-surveillance authorities.
  - EU Machinery Regulation (2023/1230) — tamper-evidence expectations for
    autonomous mobile machinery logging.

Whether this bundle is sufficient for any specific legal, regulatory, or
insurance purpose is a determination for the recipient and their counsel, not
a claim made by this document or by veriseal.

WHAT'S IN THIS BUNDLE
-----------------------
  manifest.seal.json   The signed manifest, verbatim, as produced by `veriseal seal`.
  report.txt           Human-readable verification report (this bundle's findings).
  anchor.ots           OpenTimestamps proof, if the manifest was anchored (binary).
  verify.html           Standalone, offline, client-side re-verifier (open in a browser).
  README.txt           Index of this bundle and re-verification instructions.

PROJECT
--------
veriseal is an independent, open-source tool. Source, license (Apache-2.0), and
the manifest specification: https://github.com/kylemaps/veriseal
"""

_README_TEMPLATE = """\
VERISEAL INCIDENT EVIDENCE BUNDLE
===================================

This directory is a self-contained, portable evidence package for:

  {filename}

Start here:
  1. Read cover-sheet.txt for what this bundle proves (and does not prove).
  2. Read report.txt for this bundle's specific verification findings.
  3. To re-verify independently, open verify.html in a browser (works fully
     offline — no install, no network call) and load {mcap_name} plus
     manifest.seal.json.

Files:
  cover-sheet.txt      What a seal proves / doesn't prove, and the regulatory framing.
  report.txt           Verification findings for this specific log.
  manifest.seal.json   The signed manifest (verbatim).
{anchor_line}  verify.html          Offline, independent, client-side verifier.

This bundle does NOT include the sealed log itself ({mcap_name}); it is packaged
alongside the log file, referenced by name and SHA-256 in manifest.seal.json and
report.txt. Keep {mcap_name} together with this bundle.
"""


def build_pack(
    mcap_path: Path,
    seal_path: Path,
    out_dir: Path,
    pubkey_path: Path | None = None,
) -> PackResult:
    """Build an incident-evidence bundle at *out_dir* from a sealed MCAP.

    Re-runs the same verification `veriseal verify` performs (via
    `run_verification`) and renders its result into a portable pack. Does not
    copy the MCAP itself (it may be large); the pack references it by name and
    digest and expects it to travel alongside the bundle.
    """
    manifest = json.loads(seal_path.read_bytes())
    result = run_verification(mcap_path, manifest, pubkey_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Manifest, verbatim (canonical bytes, matching what was signed/anchored).
    (out_dir / "manifest.seal.json").write_bytes(canonical_json(manifest))

    # 2. Human-readable report. Generation timestamp is explicitly out-of-band.
    generated_at = datetime.now(UTC)
    (out_dir / "report.txt").write_text(_build_report(result, generated_at), encoding="utf-8")

    # 3. OTS proof, if present, as raw binary (independently checkable with any
    #    OpenTimestamps client, not just veriseal).
    anchor = manifest.get("anchor")
    if anchor and anchor.get("ots_base64"):
        (out_dir / "anchor.ots").write_bytes(base64.b64decode(anchor["ots_base64"]))

    # 4. Offline web verifier, bundled so the recipient never has to trust a
    #    network fetch to re-check the evidence.
    if _WEB_VERIFIER.exists():
        shutil.copy2(_WEB_VERIFIER, out_dir / "verify.html")

    # 5. Cover sheet.
    (out_dir / "cover-sheet.txt").write_text(_COVER_SHEET, encoding="utf-8")

    # 6. README/index.
    anchor_line = "  anchor.ots           OpenTimestamps proof (binary).\n" if anchor else ""
    readme = _README_TEMPLATE.format(
        filename=manifest["source"]["filename"],
        mcap_name=manifest["source"]["filename"],
        anchor_line=anchor_line,
    )
    (out_dir / "README.txt").write_text(readme, encoding="utf-8")

    return PackResult(out_dir=out_dir, ok=result.ok, result=result)
