# Security policy

## Reporting a problem

Report security problems privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue.

Include what you can of the following:

- the veriseal version (`veriseal --version`) and how it was installed
- the files or steps that show the problem; a small synthetic log is ideal
- what you expected and what happened

Once a fix is released, the report is credited in the changelog unless you ask otherwise.

## What counts

veriseal exists so that a changed log fails verification. Any of these is a security problem:

- a log or seal that was changed after sealing and still verifies as intact
- a seal that verifies under a key other than the one that made it, when the verifier pinned a key
- a time anchor reported as checked against Bitcoin when it was not
- the three verifiers (Python, `web/verify.html`, the Foxglove panel) disagreeing about the same files
- a seal file or log that makes a verifier run code, read other files or contact the network unexpectedly
- a private key written with loose permissions, or left where the documentation says it is erased

## Known limits

These are part of the design, are described in the README's threat model, and are not vulnerabilities:

- A seal shows that a log is unchanged since it was sealed by a given key. It does not show that the log is true. A recorder that was already compromised can sign false data.
- Verifying without `--pubkey` trusts the key inside the seal, so a log re-sealed with a new key passes. `verify` exits `3` in that case.
- An anchor that has not been checked against Bitcoin rests on what the calendar says.

## Supported versions

Fixes go into the latest release and the `main` branch.

The streaming seal (`veriseal.stream`, `veriseal.tail`, `veriseal.witness`) is experimental. Its witness has no authentication and is meant for a private network. Reports about it are welcome, but its format and behaviour can change without a security release.
