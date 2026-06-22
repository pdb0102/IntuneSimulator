# SCEPwright

A SCEP testing suite of three tools - get a deployable cert or test a SCEP **server** (`scepclient`), test a SCEP **client** (`scepca`), or validate a server's **Intune cloud integration** (IntuneSimulator).

**`scepclient` is a SCEP client with two separate jobs.** *Use it* to get a deployable certificate from any SCEP server in a single command. *Or test with it* - point it at a server and it checks the server's RFC 8894 compliance, sending the malformed requests, wrong keys, and awkward renewals a correct CA must reject and confirming each comes back with the right `failInfo`, plus leniency findings and CI-ready reports. Post-quantum ready (ML-DSA, SLH-DSA, ML-KEM) and recipient-aware enveloping throughout. Need to test a *client* instead? `scepca` stands up a real - deliberately untrusted - CA in one command.

## Three test surfaces

- **`scepclient`** - a real RFC 8894 SCEP **client**. Get a deployable certificate in one command, or stress-test any SCEP **server** (NDES, Intune-backed, anything) for RFC compliance: every client mistake maps to the expected `failInfo`, with leniency findings, timing/Jamf simulation, and CI-ready JUnit/TRX/JSON/Markdown reports. A read-only `diagnose` reports a server's caps, CA/RA certs, and recipient verdict without issuing anything. Pluggable crypto, post-quantum (ML-DSA / SLH-DSA / ML-KEM), recipient-aware enveloping. Acts as the device when validating a server's Intune integration (`--simulator`, with IntuneSimulator). → [docs/scepclient-usage.md](docs/scepclient-usage.md)
- **`scepca` - a real SCEP server.** Issues real certificates from a built-in, **untrusted** test CA. Stand it up to test any SCEP **client**; per-profile endpoints for every RSA/EC/ML-KEM recipient shape, fault injection, persistent CA. → [docs/scepca-usage.md](docs/scepca-usage.md)
- **IntuneSimulator.** Fakes the **Intune/AAD/Graph cloud chain** so a real SCEP **server** can validate its *Intune integration* - drive the full loop with `scepclient --simulator` as the device (force failures like `SubjectNameMismatch`). The niche tool; **not** a SCEP CA. → [docs/intune-simulator.md](docs/intune-simulator.md)

`scepwright` is an umbrella dispatcher over the first two: `scepwright client …` / `scepwright test …` (the scepclient engine) and `scepwright server …` (scepca). Each tool also runs standalone.

## Algorithms at a glance

| Algorithm | What it is | `scepclient` | `scepca` |
|---|---|:--:|:--:|
| **RSA** | The classic - works with virtually every CA | ✓ | ✓ |
| **Elliptic Curve** (ECDSA) | Smaller, faster classical keys | ✓ | ✓ |
| **ML-DSA** · FIPS 204 | Post-quantum signatures (the NIST default) | ✓ | ✓ |
| **SLH-DSA** · FIPS 205 | Post-quantum signatures (hash-based alternative) | ✓ | ✓ |
| **ML-KEM** · FIPS 203 | Post-quantum key exchange | ✓ | ✓ |
| **AES / 3DES** | Encrypts the certificate request | ✓ | ✓ |
| **SHA-256 / SHA-512** | The signing hash | ✓ | ✓ |

- **Post-quantum works end to end** - both the client and the built-in CA speak ML-DSA, SLH-DSA, and ML-KEM (RFC 9629).
- **Older algorithms are included on purpose.** SHA-1, MD5, and 3DES are supported so you can test servers that still require them - not because they're recommended.
- `scepca` ships **11 ready-made server profiles** (one per key-and-encryption combination) at `/scep/<profile>` - run `scepca --help` to list them.

## Downloads

| Download | Contents | For |
|---|---|---|
| **`scepwright-<rid>.zip`** | one folder, three executables - `scepwright` (dispatcher), `scepca` (server), `scepclient` (client) + shared DLLs | testing SCEP from either side |
| **`IntuneSimulator-<rid>.zip`** | `IntuneSimulator.Host` | validating a server's Intune cloud integration |

Both are **self-contained folder publishes - never single-file.** The BouncyCastle crypto provider (`ScepWright.Crypto.BouncyCastle.dll`) is loaded by filename from the executable's directory, so it must sit on disk beside the exe. RIDs: `win-x64`, `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`.

## Quick start

```bash
# Get a cert from / test any SCEP server:
scepclient servers add https://ca.example.com/certsrv/mscep/mscep.dll --name corp
scepclient get corp --subject "CN=device-01" --challenge s3cret
scepclient test full corp --report-format junit

# Stand up a throwaway SCEP server to test a client:
scepca --port 8090 --export-ca ca.der

# One tool, both sides:
scepwright help
```

## Build from source

```bash
dotnet test          # full suite (SCEPwright.sln)
dotnet run --project src/ScepWright.Dispatcher -- help
```

Each tool maps to a project. From source, run a tool with `dotnet run --project <project> -- <args>` (everything after `--` is passed to the tool):

| Tool | Project | Example |
|---|---|---|
| `scepwright` (dispatcher) | `src/ScepWright.Dispatcher` | `dotnet run --project src/ScepWright.Dispatcher -- help` |
| `scepclient` (client) | `src/ScepWright.Client` | `dotnet run --project src/ScepWright.Client -- get corp --subject "CN=dev"` |
| `scepca` (server) | `src/ScepWright.Server.Host` | `dotnet run --project src/ScepWright.Server.Host -- --port 8090` |
| IntuneSimulator | `src/IntuneSimulator.Host` | `dotnet run --project src/IntuneSimulator.Host` |

## Docs
- [scepclient usage](docs/scepclient-usage.md)
- [scepca usage](docs/scepca-usage.md)
- [IntuneSimulator manual](docs/intune-simulator.md)
- [conformance coverage matrix](docs/coverage-matrix.md) - every suite check mapped to its RFC 8894 section
