# scepca - SCEP server usage

`scepca` is a SCEP server that issues **real certificates from a built-in, UNTRUSTED test CA**. Stand it up to test any SCEP client. (Runs standalone, or via `scepwright server …`.) Per-profile endpoints cover RSA/EC/ML-KEM recipient shapes; the CA persists across restarts so clients that trusted it stay trusting it.

> **The CA is UNTRUSTED by design.** Export it with `--export-ca <path>` and trust it explicitly in the client under test. Never use it as a real CA.

## CLI
| Flag | Default | Purpose |
|---|---|---|
| `--port <n>` | `8090` | Kestrel port. Endpoints: `/scep` and `/scep/<profile>`. |
| `--caps "<keywords>"` | `POSTPKIOperation SHA-256 AES` | advertised `GetCACaps` body |
| `--profile <name>` | all profiles | serve only this profile at `/scep` |
| `--pending` | off | every request returns PENDING (exercise client CertPoll) |
| `--challenge <pw>` | none | require this static challenge password on PKCSReq |
| `--ndes-user <u> --ndes-password <p>` | off | emulate NDES: serve the `mscep_admin` challenge page (Basic auth) that hands out one-time challenges the SCEP endpoint then accepts |
| `--export-ca <path>` | - | write the default CA cert (DER) and exit |
| `--data-dir <path>` | `~/.scepwright/ca` | persist CA state under `<path>/ca` |
| `--encrypt-keys` | off | encrypt CA/RA private keys at rest (PBES2: PBKDF2-HMAC-SHA256, ~100k iters, AES-256-CBC). Newly created profiles persist `ca.key.pkcs8.enc` instead of `ca.key.pkcs8`. |
| `--key-pass <pw>` | none | CA key passphrase - used both to encrypt on create and to decrypt on restart |

## Encrypted keys at rest
With `--encrypt-keys`, each newly created profile's CA (and split-RA) private key is written as an **encrypted PKCS#8** file - `ca.key.pkcs8.enc` (and `ra.key.pkcs8.enc`) instead of the plaintext `ca.key.pkcs8` / `ra.key.pkcs8`. The scheme is **PBES2** (PBKDF2-HMAC-SHA256, ~100 000 iterations, AES-256-CBC). On a later restart, scepca detects the `*.enc` files and decrypts them with the resolved passphrase; any standard PBES1/PBES2 scheme is accepted on read.

**Passphrase resolution** (used for both encrypt-on-create and decrypt-on-restart), in precedence order:

1. `--key-pass <pw>`
2. the `$SCEPWRIGHT_CA_KEY_PASS` environment variable
3. an interactive hidden console prompt (only when stdin is an interactive console)

If a CA key on disk is encrypted (or `--encrypt-keys` is requested on a fresh root) and **no passphrase can be resolved on a non-interactive console**, scepca **fails startup with a one-line message and a non-zero exit code** - it never prints a stack trace and never hangs waiting on stdin. A wrong passphrase fails the same way.

> The persisted key filename therefore **varies**: `ca.key.pkcs8` when keys are stored in plaintext, `ca.key.pkcs8.enc` when encrypted at rest (likewise `ra.key.pkcs8[.enc]`).

```bash
# Create + persist with encrypted keys:
scepca --encrypt-keys --key-pass s3cret --data-dir ./state --export-ca ca.der
# Restart (decrypts with the same passphrase; serves a stable GetCACert):
SCEPWRIGHT_CA_KEY_PASS=s3cret scepca --data-dir ./state
```

## NDES emulation
With `--ndes-user`/`--ndes-password`, scepca emulates NDES: every profile issues and accepts its own **one-time** challenge, and the Microsoft NDES enrollment-challenge page is served (Basic-auth gated) **parallel to each SCEP endpoint** - i.e. at `<scep-url>/mscep_admin/`, each carrying that profile's own CA thumbprint. That is exactly where the client's `NdesAdminUrl.Derive(<scep-url>)` looks, so **no explicit `--ndes-admin-url` is needed**. (The classic fixed paths `/mscep_admin/` and `/CertSrv/mscep_admin/` are also served against the default CA for real-NDES-shaped clients.) Each authorized `GET` returns the standard page with the CA thumbprint and a fresh one-time challenge that the next SCEP `PKCSReq` consumes. This makes the client's `--ndes` flow testable end to end:

```bash
scepca --port 8090 --ndes-user corp --ndes-password s3cret
# The admin URL is derived from the SCEP URL (…/scep[/<profile>] -> …/mscep_admin/) - no override needed:
scepclient enroll corp --subject "CN=router" --ndes --ndes-user corp --ndes-password s3cret
# (--ndes-admin-url is still accepted to point at a non-parallel admin page if you ever need to.)
```

## Profiles
Each profile is a CA of a given recipient shape, served at `/scep/<profile>`. The built-in profiles (sourced from `ScepServerApp.ProfileFactories()`; also listed by `scepca --help`):

| Profile | Signing CA | Envelope recipient (RA) |
|---|---|---|
| `rsa` | RSA (dual-use) | RSA (same cert) |
| `rsa-split` | RSA | RSA (separate RA) |
| `ec-encrypt` | RSA | EC (ECDH) |
| `ec-dual` | EC (dual-use) | EC (ECDH) |
| `ecdsa-rsa` | EC (ECDSA) | RSA |
| `mldsa-rsa` | ML-DSA | RSA |
| `mldsa-only` | ML-DSA (signing-only) | *(none - cannot envelope)* |
| `slhdsa-rsa` | SLH-DSA | RSA |
| `mlkem-encrypt` | RSA | ML-KEM (RFC 9629 KEMRecipientInfo) |
| `mldsa-mlkem` | ML-DSA | ML-KEM (RFC 9629) |
| `signing-only` | RSA (signing-only) | *(none - cannot envelope)* |

> **ML-KEM RA `KeyUsage`:** the `mlkem-encrypt` and `mldsa-mlkem` RA certificates assert `keyEncipherment` on an ML-KEM key. This is deliberate (it lets RecipientSelector pick the ML-KEM cert as the envelope recipient) and tracks the still-evolving LAMPS guidance on KeyUsage bits for KEM certificates; a future profile may switch to a dedicated bit once that guidance settles.

> **Fixed CA serials are by design:** every profile's CA certificate uses serial `1` (and the split-RA cert serial `2`). Because this is a throwaway **untrusted** test CA, cross-profile serial uniqueness is a non-goal - don't read into two profiles sharing serial `01`. Issued **leaf** certificates do get distinct (time-based) serials.

## Persistence
On startup, per profile: load the persisted CA if present, else generate and persist it (best-effort; never fails if the root is unwritable). Result: stable `GetCACert` and issuance across restarts. Layout: `~/.scepwright/ca/<profile>/{ca.cert.der, ca.key.pkcs8, sigalg.txt}` (plus `ra.cert.der` + `ra.key.pkcs8` for split-RA profiles). When keys are encrypted at rest (`--encrypt-keys`), the key filename is `ca.key.pkcs8.enc` (and `ra.key.pkcs8.enc`) instead - see [Encrypted keys at rest](#encrypted-keys-at-rest). Override the root with `--data-dir <path>` or the `$SCEPWRIGHT_HOME` environment variable; default `~/.scepwright/ca`.

## Hosting
- **Standalone:** `scepca --port 8090` (Kestrel).
- **IIS:** publish the folder and point an IIS site at it; the included `web.config` configures in-process hosting (ASP.NET Core Module), exactly like IntuneSimulator.

## Examples
```bash
scepca --port 8090 --export-ca ca.der      # write CA cert, trust it in your client
scepca --port 8090 --challenge s3cret      # require a challenge password
scepca --pending                           # force PENDING to test client polling
```
