# Intune Simulator

A standalone, embeddable .NET 8 simulator of Intune's SCEP validation service and the surrounding services (AAD/MSAL instance discovery, OpenID configuration, MS Graph service discovery, Intune SCEP actions, and PKI-connector revocation) for testing SCEP-server Intune integration without connecting to real Intune or Azure AD. The simulator runs as a self-contained HTTP/HTTPS server, implements the full call chain that the Microsoft SCEP PKI connector uses, and supports injecting every category of failure at every hop so that product test suites can exercise error handling end-to-end.

---

## Build & run

```bash
dotnet run --project src/IntuneSimulator.Host
```

Default ports: HTTP **8080**, HTTPS **8443**. On startup the simulator prints a banner listing all the URLs to configure in your product, the auth password, and the challenge password. It also writes **`FAILURE-FLOW.md`** beside the executable (the full 32-step failure matrix). Use `--print-failure-doc` to print the same matrix to stdout and exit without starting the server.

Run `dotnet run --project src/IntuneSimulator.Host -- --help` for all options. Key flags:

| Flag | Default | Description |
|---|---|---|
| `--http-port` | `8080` | HTTP listener port |
| `--https-port` | `8443` | HTTPS listener port |
| `--auth-password` | `IntunePassw0rd!` | Client-secret accepted for token requests |
| `--tenant` | `contoso.onmicrosoft.com` | Tenant name embedded in AAD endpoint paths |
| `--app-id` | `0000000a-0000-0000-c000-000000000000` | Application (client) ID accepted for auth |
| `--tls-cert` | *(auto-generated)* | Path to a PFX certificate for HTTPS |
| `--tls-cert-password` | | Password for the PFX |
| `--no-revocation` | | Disable the revocation endpoint |
| `--failure-mode` | `off` | Start in `manual` or `auto` failure-flow mode |
| `--advertised-base-url` | `https://localhost:<https-port>` | Base URL advertised in Graph discovery (needed for IIS) |
| `--challenge-password` | *(derived from auth password)* | Override the SCEP challenge password |
| `--print-failure-doc` | | Print the failure-flow matrix and exit |

---

## Configure your product

Point every Intune-related product setting at the simulator. All URLs must resolve from the machine running the SCEP server.

| Product setting | Set to |
|---|---|
| `ScepIntuneAuthenticationAuthorityResourceURL` | `https://localhost:8443/`  — **MUST be the https URL; MSAL requires https for the authority** |
| `ScepIntuneMSGraphResourceURL` | `https://localhost:8443/` |
| `ScepIntuneGraphResourceURL` | `https://localhost:8443/` |
| `ScepIntuneResourceURL` | `https://localhost:8443/` |
| `ScepIntuneTenantName` | `contoso.onmicrosoft.com` (or the value of `--tenant`) |
| `ScepIntuneApplicationId` | `0000000a-0000-0000-c000-000000000000` (or the value of `--app-id`) |
| `ScepIntuneApplicationSecret` | the auth password (`IntunePassw0rd!` by default) or a configured certificate |

> **Note on the authority URL:** `ScepIntuneAuthenticationAuthorityResourceURL` must use `https` because MSAL rejects non-https authority URLs. The other URL settings (`MSGraph`, `Graph`, `Resource`) may use `http`, but pointing them all at the https base is simplest. The Intune SCEP service base URL is *discovered automatically* through the Graph service-principals endpoint; the simulator advertises it pointing back at itself, so you do not need to set a separate SCEP service URL.

---

## Trust the TLS cert

The simulator auto-generates a self-signed RSA-2048 certificate on first run and stores it under `sim-tls/` beside the executable. The machine running the SCEP server (and any test process calling MSAL) must trust this certificate because .NET's `HttpClient` and MSAL validate TLS by default.

The generated cert carries the attributes a server cert needs to validate cleanly once trusted: `BasicConstraints` CA, `serverAuth` extended key usage, key usage flags, and Subject Alternative Names for `localhost`, `127.0.0.1`, `::1`, and the machine hostname. It is persisted and reused across restarts so its thumbprint stays stable once you've trusted it. (If you're upgrading from an earlier build, the old minimal cert is regenerated automatically on the next run — you'll need to re-trust the new one.)

**Download the public cert:**

```
GET https://localhost:8443/sim-cert.cer
```
The startup banner also prints the cert's path and thumbprint.

**Trust it:**

- **Windows (command line, elevated):**
  ```cmd
  curl -k -o sim-cert.cer https://localhost:8443/sim-cert.cer
  certutil -addstore -f Root sim-cert.cer
  ```
- **Windows (UI):** Double-click `sim-cert.cer` → Install Certificate → **Local Machine** → Place in "Trusted Root Certification Authorities".
- **For a permanent IIS test server:** Supply a real certificate or an enterprise CA cert via `--tls-cert <path.pfx> --tls-cert-password <pwd>` so the machine already trusts the issuer.

### Troubleshooting: "The remote certificate is invalid according to the validation procedure"

This means the TLS handshake reached the simulator but cert validation failed. The usual causes, in order of likelihood for a server product:

1. **Wrong trust store (most common for a service).** "Current User → Trusted Root" only covers processes running as *you*. If the SCEP server runs as a **Windows service** (LocalSystem, NetworkService, or a service account), it uses the **Local Machine** store instead. Install into Local Machine: `certutil -addstore -f Root sim-cert.cer` from an **elevated** prompt, or `certlm.msc` → Trusted Root Certification Authorities → import.
2. **You trusted a stale cert.** The simulator regenerates its cert if `sim-tls/sim-cert.pfx` is missing (ran from a different folder, cleaned `bin/`, deleted `sim-tls/`, or upgraded from an older build). Re-download `sim-cert.cer` and compare its thumbprint to the one in your store; re-trust if they differ. The startup banner prints the current thumbprint.
3. **Hostname not in the SAN.** Connect via a name the cert covers — `https://localhost:8443/` (or `127.0.0.1`, `::1`, or the machine hostname). The authority/Graph/resource URLs you configure must use one of those. A different name (FQDN, or `login.microsoftonline.com` via a hosts redirect) won't match the auto cert.

**See the exact reason:** the .NET message collapses several `SslPolicyErrors` into one. Inspect the served cert to tell name-mismatch from untrusted-root:
```bash
openssl s_client -connect localhost:8443 -servername localhost </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName,basicConstraints,extendedKeyUsage
```

**Bulletproof alternative — skip the self-signed dance entirely:** issue a locally-trusted cert with [`mkcert`](https://github.com/FiloSottile/mkcert) (it installs a local CA into your trust stores, so nothing else to trust) and hand it to the simulator:
```bash
mkcert -install
mkcert -pkcs12 -p12-file sim.pfx localhost 127.0.0.1 ::1
# then run the simulator with:
#   --tls-cert sim.pfx --tls-cert-password changeit
```
For a permanent IIS test server, an internal-CA / enterprise cert via `--tls-cert` is the least-fiddly option.

---

## Get the challenge password

The SCEP challenge password is the value your CA software must send in SCEP requests to authenticate them.

- **Web page:** `GET https://localhost:8443/challenge` — renders an HTML page with the base64 challenge password ready to copy and the full list of product-setting URLs.
- **JSON:** `POST https://localhost:8443/challenge` (empty body or `{}`) — returns JSON:
  ```json
  {
    "urls": {
      "authUrl": "https://localhost:8443/",
      "msGraphUrl": "https://localhost:8443/",
      "graphUrl": "https://localhost:8443/",
      "intuneResourceUrl": "https://localhost:8443/",
      "tenant": "contoso.onmicrosoft.com",
      "appId": "0000000a-0000-0000-c000-000000000000",
      "authPassword": "IntunePassw0rd!"
    },
    "challengePassword": "<base64>",
    "cannedScepCode": null,
    "revocationEnabled": true
  }
  ```
- **Default:** The challenge password is derived from the auth password. Override with `--challenge-password` on startup or via `POST /control` at runtime.

---

## Control behavior

The control endpoint lets you read and change simulator settings at runtime without restarting.

- **Web page:** `GET /control` — renders an HTML page showing all current settings.
- **JSON API:** `POST /control` with a JSON body; an empty object (`{}`) reads all settings, and any fields you include are applied.

**Read all settings:**
```bash
curl -s -X POST http://localhost:8080/control -H 'Content-Type: application/json' -d '{}'
```

**Set a canned SCEP error** (the simulator returns this error code on every SCEP action until cleared):
```bash
curl -s -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"cannedScepCode":"SubjectNameMismatch"}'
```
Clear it:
```bash
curl -s -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"cannedScepCode":null}'
```

**Set the auth password** (affects all subsequent token requests):
```bash
curl -s -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"authPassword":"s3cret"}'
```

**Set the challenge password:**
```bash
curl -s -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"challengePassword":"myNewPassword"}'
```

**Enqueue a revocation** (the simulator records SCEP revocation requests and lets tests assert them):
```bash
curl -s -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"enqueueRevocation":[{"requestContext":"ctx","serialNumber":"01AF","issuerName":"CN=MyCA","caConfiguration":"cfg"}]}'
```

**Inspect recorded requests** — `GET /control/requests` returns the SCEP/revocation requests the simulator has received (JSON array of `{endpoint, body, at}`); `DELETE /control/requests` clears them — useful for asserting from an external/out-of-process test suite:
```bash
# List all recorded requests:
curl -s http://localhost:8080/control/requests

# Clear the recorded requests:
curl -s -X DELETE http://localhost:8080/control/requests
```

---

## Failure-flow testing

When failure-flow is enabled, each verification attempt fails at exactly one point in the Intune call chain, stepping through every failure mode of every endpoint in order, and then succeeds on the final attempt. This lets you drive your product through every error-handling branch without mocking.

The chain has **32 steps** (across 6 endpoints). The full matrix is documented in **`FAILURE-FLOW.md`** (written beside the executable on startup) and can also be printed with:

```bash
dotnet run --project src/IntuneSimulator.Host -- --print-failure-doc
```

By default the simulator returns soft HTTP status codes and adds an `X-Sim-Injected: <Mode>` header so your tests can assert which failure was injected. Set `{"failureFlow":{"hardFaults":true}}` to make `Timeout` and `ConnectionRefused` steps produce real socket-level faults (useful when testing against a real Kestrel listener).

### Manual mode (deterministic — recommended for unit/integration tests)

```bash
# Enable manual mode and jump to step 5:
curl -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"failureFlow":{"mode":"manual","action":"setStep","step":5}}'

# Advance one step:
curl -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"failureFlow":{"action":"advance"}}'

# Reset to step 0:
curl -X POST http://localhost:8080/control -H 'Content-Type: application/json' \
  -d '{"failureFlow":{"action":"reset"}}'

# Convenience shortcut — enable manual mode at step 0:
curl -X POST http://localhost:8080/control/failure/manual
```

### Auto mode (advances automatically)

```bash
# Enable auto mode — advances on each fresh verification attempt:
curl -X POST http://localhost:8080/control/failure/auto
```

> **Always reset between test runs.** If a test run is aborted mid-chain the step cursor stays where it stopped, which will cause the next run to start from the wrong step. Call `POST /control {"failureFlow":{"action":"reset"}}` (or `POST /control/failure/manual` followed by reset) in your test teardown.

---

## Embed in a test suite

### .NET 8 / .NET 9 in-process (fastest)

Use `WebApplicationFactory<Program>` from `Microsoft.AspNetCore.Mvc.Testing` to host the simulator in the same process as your test:

```csharp
// See tests/IntuneSimulator.Tests/SimulatorAppFactory.cs for the full implementation.
using var factory = new SimulatorAppFactory();
var client = factory.CreateClient();
```

For tests that exercise real MSAL (which validates TLS), use the real-loopback pattern in `tests/IntuneSimulator.Tests/E2E/LoopbackServer.cs`. This starts Kestrel on a local port with the simulator's self-signed cert and creates an `HttpClient` that trusts that cert, bypassing machine-level trust.

### .NET Framework 4.8 product test suite

Publish the Host and run it as an external process:

```bash
dotnet publish src/IntuneSimulator.Host -c Release -o ./intune-sim-out
./intune-sim-out/IntuneSimulator.Host --https-port 8443 --auth-password "yourSecret"
```

Then point all `ScepIntune*` product settings at `https://localhost:8443/` as described above. Trust the cert downloaded from `GET /sim-cert.cer`. Call `POST /control` to drive failure-flow from your test code.

---

## IIS hosting

```bash
dotnet publish src/IntuneSimulator.Host -c Release -o ./publish
```

Point an IIS site at the `./publish` directory. The included `web.config` configures in-process hosting via the ASP.NET Core Module (ANCM). Set the `AdvertisedBaseUrl` environment variable (or pass `--advertised-base-url`) to the site's external `https://` URL so that Graph service-discovery responses advertise the correct base:

```xml
<environmentVariable name="AdvertisedBaseUrl" value="https://intune-sim.corp.example.com/" />
```

Configure the IIS site binding with a real or enterprise-CA certificate so that the SCEP-server machine trusts it without importing a self-signed cert.

---

## Tests

```bash
dotnet test
```

Runs the full suite (59 tests total), including a real-MSAL end-to-end test that drives the actual Microsoft sample validator classes against the simulator over loopback TLS for both client-secret and certificate authentication.

To run just the failure-doc test:

```bash
dotnet test --filter FailureDocTests
```
