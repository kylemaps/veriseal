# Contributing to veriseal

Bug reports, questions and pull requests are welcome. For anything larger than a small fix, open an issue first so the approach can be agreed before you write the code.

Report security problems privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Set up

veriseal needs Python 3.11 or newer.

```bash
git clone https://github.com/kylemaps/veriseal.git
cd veriseal
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[ros1]" --group dev
```

## Before you open a pull request

```bash
pytest                 # the whole suite takes under a minute
ruff check .
ruff format .
```

CI runs the same three commands on Linux, macOS and Windows with Python 3.11 and 3.12, and builds the Foxglove panel.

- **Tests run offline.** No test may need the network. Anything that talks to a timestamp calendar, a block explorer or a witness is tested against a local stand-in.
- **Tests use synthetic logs.** Do not add recordings from a real robot, or anything else that could hold private data.
- **A bug fix comes with a test** that fails without the fix.

## Changes to verification

The checks that decide whether a seal is valid exist in three places, and they must agree:

| Where | What |
|---|---|
| `src/veriseal/` | The Python reference |
| `web/verify.html` | The browser verifier |
| `veriseal-panel/src/sealcore.ts` | The Foxglove panel |

A change to hashing, canonical JSON, the Merkle tree or the signed payload has to be made in all three, and in [SPEC-manifest.md](SPEC-manifest.md). The files in `conformance/` and the contract tests exist to catch drift between them. Run the panel's tests with `npm test` in `veriseal-panel/`.

A change to the `veriseal-manifest-v1` format that would make an existing seal fail to verify needs a new schema version.

The streaming seal (`veriseal.stream`, `veriseal.tail`, `veriseal.witness`) is experimental and specified in [SPEC-stream.md](SPEC-stream.md). Its format can still change, and a change to it must update that document in the same pull request.

## Style

- Code is formatted by `ruff format` with a line length of 100.
- Comments and docs use plain words and say what the code does and why. Error messages say what went wrong and what to do about it.
- Docs never claim more than the tool shows: a seal shows a log is unchanged since it was sealed, not that the log is true.
- Commit subjects follow `type(scope): summary`, for example `fix(verify): reject a manifest with a float`. Common types are `feat`, `fix`, `docs`, `test` and `chore`.
- User-visible changes get a line in [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Licence

veriseal is licensed under Apache-2.0. By contributing you agree that your contribution is licensed under the same terms.
