# Persona-review backlog (history)

Findings from the external persona-driven reviews of SCEPwright (process: `TestPersonas.md`).
**Everything here is resolved** - this file is kept as a thin historical record. For the live,
forward-looking backlog see `Backlog.md`; for design decisions / accepted tradeoffs see `design.md`;
for the full per-finding detail see the git history.

## Status

**All rounds resolved; 392 tests green (67 IntuneSimulator + 325 ScepWright), 0 warnings.**

- **Rounds 1-3** (8-persona UX/security reviews): 38 items fixed + 4 deliberate by-design `[~]`.
  Covered CLI contract, key-at-rest (PBES2/AES-256, encrypted-cert renew, PFX/PEM export),
  CA + leaf X.509 extensions (`openssl verify` OK), `min-rsa-bits` enforcement, `diagnose` /
  `getcacert -v`, conformance checks #11-15 (nonce/replay/weak-cipher/spoofed-subject/coverage
  matrix), SAN flag, SHA-1 warnings, exit-code/report clarity, and doc fixes. All TDD'd and
  (where applicable) live-verified vs scepca + OpenSSL.
- **Round 4** (focused adversarial white-box pass): 10 items #43-52 - one real correctness bug
  (#43, conformance checks false-PASS a CA that can't issue) plus an edge/robustness cluster
  (scepca 500 on malformed POST, non-ASCII DNS SAN corruption, `scepca version` booting a server,
  `--export-ca` eating the next flag, blank-arg handling, `servers` flag/exit gaps). All fixed
  reproduce-before-fix; #52 turned out to be a stale-build observation (no bug). Detail in memory
  `scepwright-restructure-status` and the git history.

## By-design (deliberate; do not "fix")

These were reviewed and intentionally left as-is for a test tool; rationale at the call sites and
in `design.md` Sec 12:

- PENDING reported with a console reason (not a failure).
- Fixed CA serials (CA = 1, RA = 2).
- IntuneSimulator auth validation is deliberately lenient (test double).
- IntuneSimulator failure-flow `Reset()` -> step 0 (the documented 0-based model).
