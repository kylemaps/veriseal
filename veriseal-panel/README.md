# veriseal Seal Check: a Foxglove panel

A Foxglove Studio panel that checks a [veriseal](https://github.com/kylemaps/veriseal) seal
without leaving Foxglove. Open a log, load its `.seal.json`, and a live badge tells you whether
the seal is authentic to its signer:

- **SIGNER VERIFIED**: the signature is valid and was made by the key you pinned, and the
  manifest is internally consistent. The raw file is not checked in the panel.
- **AUTHENTICITY NOT ESTABLISHED**: the signature is valid, but no signer key is pinned.
- **MANIFEST INVALID**: the manifest is not internally consistent, or it was not signed by the
  key you pinned.
- **CANNOT CHECK**: the seal file couldn't be parsed or checked. The panel shows the reason.

## What it checks

A Foxglove panel only receives deserialized messages, never the raw serialized bytes that
veriseal hashes into Merkle leaves, so the panel checks what it can compute from the seal file:

1. Manifest signature: the seal is authentic to its Ed25519 key (WebCrypto).
2. Signer pin: paste the signer's public key (obtained out-of-band) into the panel's key
   field. The badge is green only when the seal was signed by that key; without a pinned key it
   stays amber, because the key embedded in the seal says nothing about who signed.
3. Merkle root: the listed message hashes fold to the signed root (RFC 6962).
4. Sealed window: the message count, time range and anchor status recorded in the seal.
5. Coverage: topics loaded in this view that the seal does not cover are flagged.

It does not recompute the whole-file SHA-256 of the `.mcap`, because a panel can't see the file
bytes. That check, which catches any byte-level edit, is done by `veriseal verify` on the CLI or
by the standalone [web verifier](../web/verify.html), which have the raw file.

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
