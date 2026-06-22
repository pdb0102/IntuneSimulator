**SCEPwright** — a SCEP testing suite with three test surfaces: a SCEP **client** (`scepclient`), a SCEP **server** with a built-in untrusted CA (`scepca`), and **IntuneSimulator** (fakes the Intune cloud chain to validate a server's Intune integration). The `scepwright` dispatcher fronts the client and server in one binary; each tool also runs standalone.

## Downloads

| Download | Contents | For |
|---|---|---|
| `scepwright-<rid>.zip` | `scepwright` + `scepca` + `scepclient` + shared DLLs (one folder) | testing SCEP from either side |
| `IntuneSimulator-<rid>.zip` | `IntuneSimulator.Host` | validating a server's Intune cloud integration |

Self-contained folder publishes (runtime bundled, no install). Never single-file — the provider `ScepWright.Crypto.BouncyCastle.dll` loads by filename from beside the exe. RIDs: win-x64, linux-x64, linux-arm64, osx-x64, osx-arm64.

## scepclient — SCEP client
- RFC 8894 GetCACaps/GetCACert/GetNextCACert, PKCSReq enroll, renew (multiple variants), CertPoll, GetCert, GetCRL.
- Compliance engine: client-mistake → expected `failInfo`, leniency findings, `test lifecycle|full|probe`, scenario playlists, Jamf timing simulation, JUnit/TRX/JSON/Markdown reports.
- **Recipient-aware enveloping:** picks the CA encryption cert by KeyUsage; RSA key-transport, EC ECDH key-agreement, and **ML-KEM `KEMRecipientInfo` (RFC 9629, PQ Tier C)**.
- **Classical keys:** RSA and **EC subject keys** (P-256/384/521, ECDSA) — pick with `--key-spec rsa:2048` / `ec:p384`.
- **Post-quantum:** ML-DSA / SLH-DSA CMS signing, ML-KEM enveloping; subject key specs `rsa:`, `ec:`, `ml-dsa:`, `slh-dsa:` (ML-KEM is a recipient/encryption algorithm, not a certificate subject key).
- Pluggable `IScepCrypto` provider; capability-gated clean failures; encrypted-PKCS#8 key storage; `sha256:` log redaction.

## scepca — SCEP server
- Real certificates from a built-in, **UNTRUSTED** test CA (export with `--export-ca`, trust explicitly).
- Per-profile endpoints (`/scep/<profile>`) for RSA/EC/ML-KEM recipient shapes; configurable `GetCACaps`.
- Fault injection (`--pending`, challenge enforcement, failInfo ladder); per-profile CA persistence (stable GetCACert across restarts).
- Hosts under Kestrel and IIS (`web.config`, in-process).

## IntuneSimulator
- Fakes AAD/MSAL, MS Graph discovery, Intune SCEP actions, and PKI-connector revocation; deterministic 32-step failure-flow engine; `/control` runtime behavior endpoint. Verified against real MSAL.NET. (Full manual: docs/intune-simulator.md.)

## Requirements
- .NET 8 (projects target `net8.0`).

## Known limitations
- IntuneSimulator runtime behavior state is in-memory and resets on restart.

Repo: https://github.com/pdb0102/SCEPwright
