# SCEPwright - Backlog

Tracked, actionable work. Add items as they come up; move them to **Done** (or delete) when
resolved. For the design rationale behind deferred items see `design.md`; for the per-suite
conformance coverage see `coverage-matrix.md`; for the history of external persona-review findings
(all resolved) see `persona-backlog.md`.

---

## Active

- **Enable `EnforceCodeStyleInBuild`.** The `.editorconfig` house style is currently enforced only
  via the IDE / `dotnet format` (`EnforceCodeStyleInBuild` is OFF). Flip it on once the tree is
  verified clean under it, so style violations fail the build.

---

## Deferred / considered (do not start without re-deciding)

These were consciously decided against; the rationale lives in `design.md`.

- **SCEP subject-mismatch end-to-end test** - closed as *documented, not built*. The real workflow
  is `scepclient` + IntuneSimulator against a real SCEP server (`--simulator <url>`); a
  `scepclient -> scepca -> simulator` loop would force MSAL/Graph/PKI-connector libraries into the
  deliberately-tiny `scepca`. See `design.md` Sec 12.
- **Dedicated PKIX/ASN.1 library** - would let the domain objects own ASN.1 encoding and shrink the
  crypto interface to pure primitives. Seam kept clean for it; not built (YAGNI). See `design.md`
  Sec 14.
- **GUI** - the event model and no-throw library API support one; no GUI planned now.
- **Composite (classical + PQ) signing** in the built-in provider - stays vocabulary + opinion only.
- **DRY the duplicated ML-KEM decrypt path** - explicitly **rejected**; the duplication keeps
  `scepca` standalone. See `design.md` Sec 12 before ever revisiting.

---

## Done

- Suite restructure (5a-5d): rebrand to SCEPwright, three-tool suite + dispatcher, standalone
  `scepca` library/host, per-profile CA persistence, ship docs + release workflow.
- EC subject keys; key-spec / capability honesty audit; capability-driven advice.
- Post-quantum: ML-DSA / SLH-DSA subject keys (Tier A), catalyst alt-key probe (Tier B), ML-KEM
  recipient enveloping (Tier C, RFC 9629).
- ML-KEM removed as a subject `--key-spec` (a KEM cannot be a certificate subject key); it remains
  a recipient/encryption algorithm only.
- External persona-review rounds 1-4 + the Round-4 adversarial backlog (#43-52) + a whole-codebase
  code review + CA-key-at-rest encryption. Full per-finding history in `persona-backlog.md`.
- NDES server emulation (`scepca --ndes-*`) and the client NDES challenge scrape.
