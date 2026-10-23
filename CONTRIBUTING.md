# Contributing

Thanks for taking an interest. This project is a from-scratch implementation of
the Cyberspace v2 specification, so the most valuable contribution is usually a
test that pins a rule down, not a new abstraction.

## Setting up

```bash
git clone https://github.com/ayushnandi718-dev/cyberspace-py
cd cyberspace-py
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # POSIX
pip install -e ".[dev]"
```

The core protocol needs only the standard library. `[dev]` adds pytest,
`cryptography`, `bcrypt` and `passlib` for the auditing tools and the tests.

## Running the checks

```bash
python -m pytest              # the whole suite, about two and a half minutes
python -m pytest tests/test_sidestep.py -q   # one module while you work
python -m ruff check src tests
```

`PYTHONPATH=src` (or `$env:PYTHONPATH="src"` in PowerShell) is enough to run the
suite without installing. Ruff is configured in `pyproject.toml` with a line
length of 100 and the `E`, `F`, `I`, `UP` and `B` rule sets; keep it clean.

The conformance runners are part of the public surface, so they are also a good
smoke test:

```bash
cs vectors      # the 140 chain-rule vectors of spec section 8.12
cs audit        # the audit report
cs forgery      # the local forgery experiments
cs gps          # the golden GPS vectors of spec section 9.8
```

## What makes a good test

* **Quote the rule.** Name the section of the specification the assertion comes
  from, in the test docstring. If a test fails later, the reviewer should be able
  to open the spec and check which side is wrong.
* **Prefer the normative vector.** Where the specification or the upstream
  repository publishes a vector (chain rules, GPS, visualization, BIP-340), the
  test should use it verbatim. Vendored fixtures live in `tests/fixtures/`.
* **Use the cheap positions.** A spawn coordinate is the identity's public key
  read as a coordinate, and each axis root is sampled at the same height, so a
  base of zero at height `h` is `compute_subtree_cantor(0, h)`, not zero. One
  low-bit neighbour step keeps proof heights at 1 and the suite fast.
* **Do not assert on the order of an unordered result** unless the code sorts it
  deliberately.

## Ground rules

* **Nothing is ported from another implementation.** The specification text and
  the published vectors are the only sources. Reading a reference implementation
  to resolve an ambiguity is fine if you say so in the pull request; copying its
  code is not.
* **The spec is read-only.** Do not edit the upstream checkout. If the text is
  ambiguous, implement the reading that the vectors support and note the
  ambiguity in the docstring.
* **Keep the core dependency-free.** `import cyberspace` must work on a bare
  Python 3.10+ installation. Optional dependencies belong behind the extras.
* **Security tooling stays defensive.** `secsuite` and `redteam` analyse systems
  the operator owns or is authorised to test. Contributions that add
  persistence, stealth, credential theft or network exploitation are out of
  scope.

## Known gaps

These are good places to start if you want something substantial:

* **DECK-0003 `sno`.** The DECK is not implemented yet, nor is the palette it
  describes.
* **Android parsers.** The AXML and DEX readers are import-smoke-tested only.
  Golden vectors from real APKs would let them be checked properly.
* **Argon2.** Argon2 hashes are identified and dispatched, but `argon2-cffi` is
  not installed by default, so they cannot be computed in the test suite.
* **Live network checks.** `secsuite tls`, `http` and `scan` are verified
  offline. If you test them against a host, do so only with permission.

## Licence

Code is MIT. The specification text and the vendored vectors are CC BY-SA 4.0
by arkin0x; see `NOTICE`. By contributing code you agree to license it under the
MIT terms, and by contributing a vector or quotation you agree to the terms it
already carries.
