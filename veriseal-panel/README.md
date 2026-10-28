# veriseal Seal Check — Foxglove panel

A Foxglove Studio panel that checks a [veriseal](https://github.com/kylemaps/veriseal) seal
**without leaving your visualization**. Open a log, load its `.seal.json`, and a live badge tells
you whether the seal is authentic to its signer:

> **SIGNER VERIFIED** — signature valid & pinned to your key · internally consistent · raw file not checked in-panel
>
> **AUTHENTICITY NOT ESTABLISHED** — signature valid, but no signer key pinned
>
> **MANIFEST INVALID** — the manifest is not internally consistent, or the signer key doesn't match the one you pinned
>
> **CANNOT CHECK** — the seal file couldn't be parsed or checked (the reason is shown)

## What it checks (and what it doesn't)

A Foxglove panel only ever receives **deserialized** messages — never the raw serialized bytes
that veriseal hashes into Merkle leaves. So this panel is deliberate about its claims. It verifies:

1. **Manifest signature** — the seal is authentic to its Ed25519 key (WebCrypto).
2. **Signer pin** — paste the signer's public key (obtained out-of-band) into the panel's key
   field. The badge is green only when the seal was signed by that key; without a pinned key it
   stays amber, because the key embedded in the seal proves nothing about who signed.
3. **Merkle root** — the listed message hashes fold to the signed root (RFC 6962).
4. **Sealed window** — message count, time range, and anchor status recorded in the seal.
5. **Coverage** — flags topics loaded in this view that the seal does not cover.

It does **not** recompute the whole-file SHA-256 of the `.mcap`, because a panel can't see the
file bytes. That check — the one that catches an edited log byte-for-byte — belongs to
`veriseal verify` on the CLI or the standalone [web verifier](../web/verify.html), which have the
raw file. The panel is honest about this boundary rather than faking a proof it can't compute.

The verification core ([`src/sealcore.ts`](src/sealcore.ts)) mirrors the Python reference in
`../src/veriseal/` byte-for-byte (canonical JSON, RFC 6962 Merkle, Ed25519). `npm test` compiles
it and asserts equivalence against a manifest sealed by the real CLI, plus tamper cases.

## Develop

```sh
npm install
npm run build          # type-check + bundle to dist/
npm test               # verify the core matches the Python reference
npm run local-install  # install into your local Foxglove for testing
npm run package        # produce kylemaps.veriseal-panel-<version>.foxe
```

Requires a Foxglove build with WebCrypto Ed25519 (recent Chromium/desktop). After
`local-install`, open Foxglove (or press `ctrl-R` to refresh) and add the **veriseal · Seal
Check** panel.

## Use

1. Add the **veriseal · Seal Check** panel to your layout.
2. Open your sealed `.mcap` as usual.
3. In the panel, choose the log's `.seal.json` manifest.
4. Read the badge. To pin a signer you trust, compare the shown key fingerprint against the one
   you hold out-of-band.

## Publish

Extensions package into `.foxe` files. See the Foxglove
[publishing docs](https://docs.foxglove.dev/docs/visualization/extensions/publish/).
