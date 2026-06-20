# ScepTestClient Phase 4 — PQ & Composite + Provider Polish — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-extended-cc:subagent-driven-development (recommended) or superpowers-extended-cc:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add post-quantum vocabulary and tier-A/B capability to the BouncyCastle provider (ML-DSA / SLH-DSA end-entity keys + catalyst alt-key), make the loaded provider's capabilities drive opinion/probe/suggest, ship `crypto info`/`crypto list`, and harden external-provider loading via `--crypto-provider`/config — all additively, with no `IScepCrypto` signature changes.

**Architecture:** All PQ support slots in through the three additive seams validated in Phase 1 (open OID identifiers + capability advertisement; opaque `IScepKey` handles; extensible domain objects). The `IScepCrypto` *interface is not changed*. New surface is limited to: registry entries, `KeySpec` PQ parsing, one `CryptoCapabilities.PqTiers` property, one `Pkcs10.AltKey` property, and provider-internal branching in `BouncyCastleScepCrypto`/`BcCsrBuilder`. Tier C (ML-KEM CMS envelope) is advertised but **not implemented in the built-in provider** because BouncyCastle 2.5.0's CMS layer has no `KemRecipientInfoGenerator` — it is left as a clean seam an external provider fills.

**Tech Stack:** .NET 8 (`net8.0`, `RollForward Major`); `BouncyCastle.Cryptography` 2.5.0 (only in `ScepTestClient.Crypto.BouncyCastle`); xUnit. House style enforced by `.editorconfig` (see "House style" below).

**User decisions (already made):**
- "The design is done — do NOT re-brainstorm." Plan straight from spec §14 + §3.3/§3.4/§3.5 + §17 row 4.
- "First task: re-validate the IScepCrypto seam on paper against all 3 PQ tiers ... before changing signatures — additive only." → Task 1.
- "BC provider tiers A/B ... and tier C where BC 2.5.0 allows." → Empirically confirmed: tier A/B feasible; tier C envelope **not** feasible in BC 2.5.0 (no CMS KEM recipient generator) → advertised-only.
- "capabilities driving opinion/probe/suggest (incl. AlgorithmPosture.CuttingEdge, currently unused)." → Tasks 8, 9.
- "Keep granular task commits (no squash); I'll PR via SmartGit."
- **Deferred Phase-3 item (spec §13 simulator subject-mismatch test): KEPT DEFERRED.** Rationale: it is orthogonal to PQ, belongs to the compliance engine (Phase 3 territory), and depends on IntuneSimulator-side canned-error controls that are a separate subsystem. Folding it into an already-large PQ phase would mix concerns. Re-targeted to a Phase-3 follow-up / Phase 5. Documented here so it is not lost.

---

## House style (tell EVERY subagent, verbatim)

Write all new code in the repo `.editorconfig` style **from the first keystroke** (no reformat pass):
- **Never `var`** — always the explicit type.
- **Declare all locals at the top of the block, unassigned, then a blank line, then the assignments.**
- Same-line braces; single-line statements where the file already does.
- `snake_case` for locals/params/private fields; `PascalCase` for members.
- No exceptions for control flow: sync = result/`bool` + `out value` + `out string error`; async = `ScepResult<T>`.
- All cryptography stays inside `ScepTestClient.Crypto.*`; never reference BouncyCastle outside that project.

Process reminders for subagents:
- **Implementers:** stage files **explicitly** (`git add <path> ...`); never `git add -A` (it sweeps the plan `.md`/`.tasks.json` into code commits). One commit per task.
- **Review / Explore agents:** **do NOT run `git checkout`/`git switch`** — stay on `feature/scep-test-client-phase-4`. (In Phase 2 a reviewer moved HEAD to `main` mid-run.)
- **The round-trip / e2e test is the source of truth for any BouncyCastle call.** If a BC API name/namespace below is slightly off for 2.5.0, adjust the call until it compiles and the test passes, and report the deviation. Do not change the test's intent.
- Tests instantiate the provider directly: `new BouncyCastleScepCrypto()` (there is no `TestCrypto.Load()`). `KeySpec` ctor is private → use `KeySpec.Parse(...)`.

---

## BouncyCastle 2.5.0 PQ reality (empirically probed 2026-06-20 — feed to crypto agents)

Confirmed present in `BouncyCastle.Cryptography` 2.5.0 (`lib/netstandard2.0/BouncyCastle.Cryptography.dll`):
- **ML-DSA:** `MLDsaKeyPairGenerator`, `MLDsaKeyGenerationParameters`, `MLDsaParameters` (`ml_dsa_44`/`ml_dsa_65`/`ml_dsa_87`), `MLDsaPrivateKeyParameters`/`MLDsaPublicKeyParameters`, `MLDsaSigner`/`HashMLDsaSigner`. Param-set OIDs: `id_ml_dsa_44/65/87`.
- **SLH-DSA:** `SlhDsaKeyPairGenerator`, `SlhDsaKeyGenerationParameters`, `SlhDsaParameters`, `SlhDsaPrivateKeyParameters`/`SlhDsaPublicKeyParameters`, `SlhDsaSigner`/`HashSlhDsaSigner`.
- **ML-KEM:** `MLKemKeyPairGenerator`, `MLKemParameters` (`MLKEM512/768/1024`) — **keygen + KEM primitive only**.
- **PQ ASN.1 emit/parse:** `PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub)` and `PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(priv)` (namespace `Org.BouncyCastle.Pqc.Crypto.Utilities`). `PrivateKeyFactory.CreateKey(der)` parses PQ PKCS#8 back.
- **Signature factory:** `Asn1SignatureFactory` (try `new Asn1SignatureFactory("ML-DSA-65", priv, random)`; if 2.5.0 rejects the name, wrap `MLDsaSigner` in a custom `ISignatureFactory` — round-trip test arbitrates).

Confirmed **ABSENT / not usable** in 2.5.0:
- **No CMS KEM recipient generator.** The CMS recipient-generator family is only `CmsKeyTransRecipientInfoGenerator` / `KekRecipientInfoGenerator` / `KeyAgreeRecipientInfoGenerator` / `PasswordRecipientInfoGenerator`. `KemRecipientInfo` exists only as a raw ASN.1 type. → **Tier C ML-KEM `EnvelopedData` (RFC 9629) cannot be built with the built-in provider.** Advertise the capability (TierC=false), probe empirically, document the limitation.
- **No clean current composite signature generator.** Only the legacy Dilithium-draft composite OIDs (`id_Dilithium3_ECDSA_P256_SHA256`, etc.) and the bare `id_composite_key` OID exist — no ML-DSA composite signing path. → Treat **composite** as vocabulary + opinion only (no BC signing implementation).

PQ namespaces in 2.5.0 are typically `Org.BouncyCastle.Pqc.Crypto.MLDsa`, `...Pqc.Crypto.SlhDsa`, `...Pqc.Crypto.MLKem`, `...Pqc.Crypto.Utilities`. Verify per build; the test arbitrates.

---

## File structure

New files:
- `docs/superpowers/analysis/2026-06-20-iscepcrypto-pq-seam-validation.md` — Task 1 paper validation (committed artifact).
- `src/ScepTestClient.CryptoApi/PqTiers.cs` — the additive `PqTiers` value carried by `CryptoCapabilities`.
- `src/ScepTestClient.Crypto.BouncyCastle/BcPqKeys.cs` — PQ keygen/SPKI/PKCS#8 helpers (keeps `BouncyCastleScepCrypto` readable).
- `src/ScepTestClient.Cli/CryptoCommand.cs` — `crypto info` / `crypto list` rendering (keeps `CommandRouter` lean).
- `tests/ScepTestClient.Tests/PqAlgorithmsTests.cs`, `PqKeySpecTests.cs`, `PqCapabilitiesTests.cs`, `PqKeyGenTests.cs`, `PqCsrTests.cs`, `AltKeyCsrTests.cs`, `PqOpinionSuggestTests.cs`, `PqProbeTests.cs`, `CryptoCommandTests.cs`, `CryptoProviderFlagTests.cs` (+ extend `ProviderLoadTests.cs`).

Modified files (all additive):
- `src/ScepTestClient.CryptoApi/Algorithms.cs` — PQ registry entries.
- `src/ScepTestClient.CryptoApi/KeySpec.cs` — PQ parse + new `Parameter` property.
- `src/ScepTestClient.CryptoApi/CryptoCapabilities.cs` — `PqTiers` property.
- `src/ScepTestClient.CryptoApi/Pkcs10.cs` — `AltKey` property.
- `src/ScepTestClient.Crypto.BouncyCastle/BcAlgorithms.cs` — PQ OID constants.
- `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs` — PQ keygen/export branch + PQ capabilities.
- `src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs` — PQ SPKI/signature + alt-key extension.
- `src/ScepTestClient.Core/Testing/SecurityOpinion.cs` — `ClassifySignature` (CuttingEdge).
- `src/ScepTestClient.Core/Testing/ServerSuggest.cs` — PQ suggestion driven by provider caps.
- `src/ScepTestClient.Core/Testing/TestEngine.cs` — `ProbePq` step.
- `src/ScepTestClient.Core/EnrollRequest.cs` — `AltKey` field.
- `src/ScepTestClient.Core/ScepRequestBuilder.cs` — `.AltKey(...)` + wiring.
- `src/ScepTestClient.Core/ScepClient.cs` — thread `AltKey` from `EnrollRequest` into the CSR.
- `src/ScepTestClient.Core/ProviderLoadContext.cs` / `src/ScepTestClient.Core/ScepCrypto.cs` — ALC hardening.
- `src/ScepTestClient.Core/Storage/ClientConfig.cs` — (already has `CryptoProviderPath`; add `config set` support path).
- `src/ScepTestClient.Cli/CommandRouter.cs` — `crypto` command, `--crypto-provider`/config resolution at all `ScepCrypto.Load` sites, `--alt-key-spec`, `config set`.

---

## Task 1: Re-validate the IScepCrypto seam vs all 3 PQ tiers (paper)

**Goal:** Produce a committed analysis confirming PQ support is additive-only (no `IScepCrypto` signature change), grounded in the BC 2.5.0 reality, before any code changes.

**Files:**
- Create: `docs/superpowers/analysis/2026-06-20-iscepcrypto-pq-seam-validation.md`

**Acceptance Criteria:**
- [ ] Doc walks each of the three tiers (A: ML-DSA/SLH-DSA end-entity; B: catalyst alt-key; C: ML-KEM envelope) against the current `IScepCrypto` (read at `src/ScepTestClient.CryptoApi/IScepCrypto.cs`).
- [ ] Doc states, per tier, the exact additive change required and confirms **no interface signature changes**.
- [ ] Doc records the BC 2.5.0 reality: tier A/B feasible; tier C envelope NOT feasible (no CMS `KemRecipientInfoGenerator`); composite = vocabulary/opinion only.
- [ ] Doc lists the precise new additive surface the rest of Phase 4 introduces (`KeySpec.Parameter`, `CryptoCapabilities.PqTiers`, `Pkcs10.AltKey`, registry entries).

**Verify:** `test -f docs/superpowers/analysis/2026-06-20-iscepcrypto-pq-seam-validation.md && grep -q "additive-only" docs/superpowers/analysis/2026-06-20-iscepcrypto-pq-seam-validation.md` → exit 0

**Steps:**

- [ ] **Step 1: Write the analysis doc** with this content (verbatim is acceptable; expand prose as desired):

```markdown
# IScepCrypto seam validation vs PQ tiers (Phase 4 pre-flight)

Date: 2026-06-20. Re-validates the Phase-1 on-paper conclusion before writing PQ code.
Reference interface: src/ScepTestClient.CryptoApi/IScepCrypto.cs (unchanged by Phase 4).

## Conclusion: additive-only. No IScepCrypto signature changes.

## Tier A — PQ end-entity key (ML-DSA / SLH-DSA)
- KeySpec.Parse gains "ml-dsa:65" / "slh-dsa:128s" (new accepted inputs + a new `Parameter`
  property; existing `rsa:<bits>` callers unaffected).
- IScepCrypto.GenerateKey(KeySpec, out IScepKey, out string) — unchanged signature; returns an
  IScepKey whose AlgorithmOid is the PQ OID.
- IScepCrypto.EncodeCsr(Pkcs10, ...) — unchanged; provider emits a PQ SubjectPublicKeyInfo
  (PqcSubjectPublicKeyInfoFactory) and signs with the PQ signer.
- ExportPrivateKeyPkcs8 / ImportPrivateKeyPkcs8 — unchanged; PQ via PqcPrivateKeyInfoFactory /
  PrivateKeyFactory.
- BC 2.5.0: FEASIBLE.

## Tier B — Catalyst / hybrid alt-key (subjectAltPublicKeyInfo)
- New additive Pkcs10.AltKey (IScepKey?) property, ignored by existing callers.
- EncodeCsr emits the subjectAltPublicKeyInfo extension (OID 2.5.29.72) carrying the alt key's SPKI.
- No interface change.
- BC 2.5.0: alt PUBLIC KEY emission FEASIBLE; computing a conformant altSignatureValue over the CSR
  is bleeding-edge and NOT done by the built-in provider — a ConformanceNote records this.

## Tier C — PQ transport (ML-KEM EnvelopedData, RFC 9629 KEMRecipientInfo)
- EncodePkiMessage already takes the recipient via PkiMessage.RecipientCaCert — a PQ recipient
  WOULD trigger KEMRecipientInfo inside the provider. No signature change.
- BC 2.5.0: NOT FEASIBLE — the CMS layer exposes only KeyTrans/Kek/KeyAgree/Password recipient
  generators; KemRecipientInfo is a raw ASN.1 type with no CMS generator. The built-in provider
  therefore advertises CryptoCapabilities.PqTiers.TierC = false; an external provider can implement it.

## Composite signatures
- Only legacy Dilithium-draft composite OIDs exist in 2.5.0; no ML-DSA composite signing path.
- Scope: composite stays vocabulary + opinion (CuttingEdge), no BC signing implementation.

## New additive surface introduced by Phase 4
- KeySpec.Parameter (string); KeySpec.Parse PQ inputs.
- CryptoCapabilities.PqTiers (TierA/TierB/TierC bools) + PQ OIDs in Signatures/AsymmetricKeys/Kem.
- Pkcs10.AltKey (IScepKey?).
- Algorithms registry: ML-DSA-44/65/87, SLH-DSA-*, ML-KEM-512/768/1024 entries.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/analysis/2026-06-20-iscepcrypto-pq-seam-validation.md
git commit -m "Phase 4: validate IScepCrypto seam is additive-only across all 3 PQ tiers"
```

---

## Task 2: PQ algorithm registry entries

**Goal:** Add PQ algorithms to the `Algorithms` registry with correct `AlgorithmKind` so name↔OID lookup and kind-filtering work for PQ.

**Files:**
- Modify: `src/ScepTestClient.CryptoApi/Algorithms.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcAlgorithms.cs` (add OID constants for provider use)
- Test: `tests/ScepTestClient.Tests/PqAlgorithmsTests.cs`

**Acceptance Criteria:**
- [ ] `Algorithms.OidFor("ML-DSA-65")` → `2.16.840.1.101.3.4.3.18`; `NameFor` round-trips (case-insensitive).
- [ ] `ML-DSA-44/65/87` tagged `AlgorithmKind.Signature`; `SLH-DSA-128s` tagged `Signature`; `ML-KEM-512/768/1024` tagged `AlgorithmKind.Kem`.
- [ ] Existing entries (RSA, SHA-*, AES-*) still resolve unchanged.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqAlgorithmsTests` → PASS

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqAlgorithmsTests.cs`:

```csharp
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqAlgorithmsTests {
    [Theory]
    [InlineData("ML-DSA-44", "2.16.840.1.101.3.4.3.17", AlgorithmKind.Signature)]
    [InlineData("ML-DSA-65", "2.16.840.1.101.3.4.3.18", AlgorithmKind.Signature)]
    [InlineData("ML-DSA-87", "2.16.840.1.101.3.4.3.19", AlgorithmKind.Signature)]
    [InlineData("ML-KEM-512", "2.16.840.1.101.3.4.4.1", AlgorithmKind.Kem)]
    [InlineData("ML-KEM-768", "2.16.840.1.101.3.4.4.2", AlgorithmKind.Kem)]
    [InlineData("ML-KEM-1024", "2.16.840.1.101.3.4.4.3", AlgorithmKind.Kem)]
    public void Pq_entries_resolve(string name, string oid, AlgorithmKind kind) {
        Assert.Equal(oid, Algorithms.OidFor(name));
        Assert.Equal(name, Algorithms.NameFor(oid));
        Assert.Equal(kind, Algorithms.KindOf(oid));
    }

    [Fact]
    public void Existing_entries_unchanged() {
        Assert.Equal("2.16.840.1.101.3.4.2.1", Algorithms.OidFor("SHA-256"));
        Assert.Equal("1.2.840.113549.1.1.1", Algorithms.OidFor("RSA"));
    }
}
```

- [ ] **Step 2: Run → FAIL** (`Algorithms.OidFor("ML-DSA-65")` is null).

- [ ] **Step 3: Add entries** to the `Entries` array in `Algorithms.cs` (NIST CSOR OIDs for ML-DSA `2.16.840.1.101.3.4.3.17/18/19`, ML-KEM `2.16.840.1.101.3.4.4.1/2/3`; SLH-DSA SHA2 small set OIDs `2.16.840.1.101.3.4.3.20/21/22` for 128s/192s/256s):

```csharp
        new("ML-DSA-44",   "2.16.840.1.101.3.4.3.17",       AlgorithmKind.Signature),
        new("ML-DSA-65",   "2.16.840.1.101.3.4.3.18",       AlgorithmKind.Signature),
        new("ML-DSA-87",   "2.16.840.1.101.3.4.3.19",       AlgorithmKind.Signature),
        new("SLH-DSA-128s","2.16.840.1.101.3.4.3.20",       AlgorithmKind.Signature),
        new("SLH-DSA-192s","2.16.840.1.101.3.4.3.21",       AlgorithmKind.Signature),
        new("SLH-DSA-256s","2.16.840.1.101.3.4.3.22",       AlgorithmKind.Signature),
        new("ML-KEM-512",  "2.16.840.1.101.3.4.4.1",        AlgorithmKind.Kem),
        new("ML-KEM-768",  "2.16.840.1.101.3.4.4.2",        AlgorithmKind.Kem),
        new("ML-KEM-1024", "2.16.840.1.101.3.4.4.3",        AlgorithmKind.Kem),
```

  Also add the matching OID constants to `BcAlgorithms.cs`:

```csharp
    public const string MlDsa44 = "2.16.840.1.101.3.4.3.17";
    public const string MlDsa65 = "2.16.840.1.101.3.4.3.18";
    public const string MlDsa87 = "2.16.840.1.101.3.4.3.19";
    public const string SlhDsa128s = "2.16.840.1.101.3.4.3.20";
    public const string SlhDsa192s = "2.16.840.1.101.3.4.3.21";
    public const string SlhDsa256s = "2.16.840.1.101.3.4.3.22";
    public const string MlKem512 = "2.16.840.1.101.3.4.4.1";
    public const string MlKem768 = "2.16.840.1.101.3.4.4.2";
    public const string MlKem1024 = "2.16.840.1.101.3.4.4.3";
```

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit**

```bash
git add src/ScepTestClient.CryptoApi/Algorithms.cs src/ScepTestClient.Crypto.BouncyCastle/BcAlgorithms.cs tests/ScepTestClient.Tests/PqAlgorithmsTests.cs
git commit -m "Phase 4: add ML-DSA/SLH-DSA/ML-KEM entries to the algorithm registry"
```

---

## Task 3: KeySpec accepts PQ specs

**Goal:** Extend `KeySpec.Parse` to accept `ml-dsa:<set>` and `slh-dsa:<set>` (and `ml-kem:<set>` for completeness) additively, exposing the parameter set via a new `Parameter` property, without breaking `rsa:<bits>`.

**Files:**
- Modify: `src/ScepTestClient.CryptoApi/KeySpec.cs`
- Test: `tests/ScepTestClient.Tests/PqKeySpecTests.cs`

**Acceptance Criteria:**
- [ ] `KeySpec.Parse("ml-dsa:65", ...)` → `Algorithm == "ML-DSA"`, `Parameter == "65"`, `Size == 0`, `Raw == "ml-dsa:65"`.
- [ ] `KeySpec.Parse("slh-dsa:128s", ...)` → `Algorithm == "SLH-DSA"`, `Parameter == "128s"`.
- [ ] `KeySpec.Parse("rsa:2048", ...)` → `Algorithm == "RSA"`, `Size == 2048`, `Parameter == ""` (unchanged behavior).
- [ ] Unknown algorithm (`ec:p256`) and bad PQ set (`ml-dsa:99`) → `false` with a clear error.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqKeySpecTests` → PASS (and existing `KeySpec`-using tests still green)

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqKeySpecTests.cs`:

```csharp
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqKeySpecTests {
    [Fact]
    public void Parses_ml_dsa() {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error));
        Assert.Equal("ML-DSA", spec.Algorithm);
        Assert.Equal("65", spec.Parameter);
        Assert.Equal(0, spec.Size);
    }

    [Fact]
    public void Parses_slh_dsa() {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse("slh-dsa:128s", out spec, out error));
        Assert.Equal("SLH-DSA", spec.Algorithm);
        Assert.Equal("128s", spec.Parameter);
    }

    [Fact]
    public void Rsa_unchanged() {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse("rsa:2048", out spec, out error));
        Assert.Equal("RSA", spec.Algorithm);
        Assert.Equal(2048, spec.Size);
        Assert.Equal(string.Empty, spec.Parameter);
    }

    [Theory]
    [InlineData("ec:p256")]
    [InlineData("ml-dsa:99")]
    [InlineData("slh-dsa:bogus")]
    public void Rejects_bad(string text) {
        KeySpec spec;
        string error;

        Assert.False(KeySpec.Parse(text, out spec, out error));
        Assert.NotEqual(string.Empty, error);
    }
}
```

- [ ] **Step 2: Run → FAIL** (no `Parameter`; PQ rejected).

- [ ] **Step 3: Rewrite `KeySpec`** additively — add `Parameter`, keep the private ctor signature growing by one param:

```csharp
namespace ScepTestClient.CryptoApi;

public sealed class KeySpec {
    private static readonly string[] MlDsaSets = { "44", "65", "87" };
    private static readonly string[] SlhDsaSets = { "128s", "192s", "256s", "128f", "192f", "256f" };
    private static readonly string[] MlKemSets = { "512", "768", "1024" };

    public string Algorithm { get; }
    public int Size { get; }
    public string Parameter { get; }
    public string Raw { get; }

    private KeySpec(string algorithm, int size, string parameter, string raw) {
        Algorithm = algorithm;
        Size = size;
        Parameter = parameter;
        Raw = raw;
    }

    public static bool Parse(string text, out KeySpec spec, out string error) {
        string[] parts;
        string algo;
        string param;
        int bits;

        spec = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text)) {
            error = "key spec is empty";
            return false;
        }

        parts = text.Split(':');
        if (parts.Length != 2) {
            error = $"unsupported key spec '{text}' (expected 'rsa:<bits>' / 'ml-dsa:<set>' / 'slh-dsa:<set>')";
            return false;
        }

        algo = parts[0].ToLowerInvariant();
        param = parts[1];

        if (algo == "rsa") {
            if (!int.TryParse(param, out bits) || bits < 1024) {
                error = $"invalid RSA size in '{text}'";
                return false;
            }
            spec = new KeySpec("RSA", bits, string.Empty, text);
            return true;
        }

        if (algo == "ml-dsa") {
            if (System.Array.IndexOf(MlDsaSets, param) < 0) {
                error = $"invalid ML-DSA parameter set '{param}' (expected 44/65/87)";
                return false;
            }
            spec = new KeySpec("ML-DSA", 0, param, text);
            return true;
        }

        if (algo == "slh-dsa") {
            if (System.Array.IndexOf(SlhDsaSets, param) < 0) {
                error = $"invalid SLH-DSA parameter set '{param}'";
                return false;
            }
            spec = new KeySpec("SLH-DSA", 0, param, text);
            return true;
        }

        if (algo == "ml-kem") {
            if (System.Array.IndexOf(MlKemSets, param) < 0) {
                error = $"invalid ML-KEM parameter set '{param}' (expected 512/768/1024)";
                return false;
            }
            spec = new KeySpec("ML-KEM", 0, param, text);
            return true;
        }

        error = $"unsupported key spec '{text}'";
        return false;
    }
}
```

- [ ] **Step 4: Run → PASS** (and run the full suite to confirm no `new KeySpec(...)` call sites broke — the ctor is private, only `Parse` constructs it).

- [ ] **Step 5: Commit**

```bash
git add src/ScepTestClient.CryptoApi/KeySpec.cs tests/ScepTestClient.Tests/PqKeySpecTests.cs
git commit -m "Phase 4: KeySpec.Parse accepts ml-dsa/slh-dsa/ml-kem parameter sets"
```

---

## Task 4: CryptoCapabilities PQ tiers + provider advertises PQ

**Goal:** Add an additive `PqTiers` value to `CryptoCapabilities` and have the BouncyCastle provider advertise its PQ algorithms (ML-DSA/SLH-DSA in Signatures+AsymmetricKeys, ML-KEM in Kem) and tiers (A=true, B=true, **C=false**).

**Files:**
- Create: `src/ScepTestClient.CryptoApi/PqTiers.cs`
- Modify: `src/ScepTestClient.CryptoApi/CryptoCapabilities.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs` (the `Capabilities` initializer only)
- Test: `tests/ScepTestClient.Tests/PqCapabilitiesTests.cs`

**Acceptance Criteria:**
- [ ] `CryptoCapabilities.PqTiers` defaults to all-false (existing/external callers unaffected).
- [ ] `new BouncyCastleScepCrypto().Capabilities.PqTiers` → `TierA == true`, `TierB == true`, `TierC == false`.
- [ ] Provider `Signatures` contains ML-DSA-65 OID; `AsymmetricKeys` contains ML-DSA-65 OID; `Kem` contains ML-KEM-768 OID.
- [ ] Existing capabilities (SHA/AES/RSA) still present.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqCapabilitiesTests` → PASS (and `CapabilitiesTests` still green)

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqCapabilitiesTests.cs`:

```csharp
using System.Linq;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqCapabilitiesTests {
    [Fact]
    public void Default_pqtiers_all_false() {
        CryptoCapabilities caps;

        caps = new CryptoCapabilities();
        Assert.False(caps.PqTiers.TierA);
        Assert.False(caps.PqTiers.TierB);
        Assert.False(caps.PqTiers.TierC);
    }

    [Fact]
    public void Bc_provider_advertises_pq() {
        BouncyCastleScepCrypto crypto;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(crypto.Capabilities.PqTiers.TierA);
        Assert.True(crypto.Capabilities.PqTiers.TierB);
        Assert.False(crypto.Capabilities.PqTiers.TierC);
        Assert.Contains("2.16.840.1.101.3.4.3.18", crypto.Capabilities.Signatures);
        Assert.Contains("2.16.840.1.101.3.4.3.18", crypto.Capabilities.AsymmetricKeys);
        Assert.Contains("2.16.840.1.101.3.4.4.2", crypto.Capabilities.Kem);
        Assert.Contains("1.2.840.113549.1.1.1", crypto.Capabilities.AsymmetricKeys);
    }
}
```

- [ ] **Step 2: Run → FAIL** (no `PqTiers`).

- [ ] **Step 3: Create `PqTiers.cs`:**

```csharp
namespace ScepTestClient.CryptoApi;

// PQ tier support advertised by a provider (spec §3.4, §14). Additive — defaults to all-false so
// existing/external CryptoCapabilities consumers are unaffected.
public sealed record PqTiers(bool TierA = false, bool TierB = false, bool TierC = false);
```

- [ ] **Step 4: Add the property** to `CryptoCapabilities.cs`:

```csharp
    public PqTiers PqTiers { get; init; } = new PqTiers();
```

- [ ] **Step 5: Extend the provider's `Capabilities` initializer** in `BouncyCastleScepCrypto.cs` (add PQ OIDs + tiers; keep existing entries):

```csharp
    public CryptoCapabilities Capabilities { get; } = new CryptoCapabilities {
        Digests = new[] { BcAlgorithms.Sha1, BcAlgorithms.Sha256, BcAlgorithms.Sha512, BcAlgorithms.Md5 },
        Signatures = new[] { BcAlgorithms.Rsa, BcAlgorithms.MlDsa44, BcAlgorithms.MlDsa65, BcAlgorithms.MlDsa87,
                             BcAlgorithms.SlhDsa128s, BcAlgorithms.SlhDsa192s, BcAlgorithms.SlhDsa256s },
        ContentEncryption = new[] { BcAlgorithms.Aes128Cbc, BcAlgorithms.Aes256Cbc, BcAlgorithms.Des3Cbc },
        KeyTransport = new[] { BcAlgorithms.Rsa },
        Kem = new[] { BcAlgorithms.MlKem512, BcAlgorithms.MlKem768, BcAlgorithms.MlKem1024 },
        AsymmetricKeys = new[] { BcAlgorithms.Rsa, BcAlgorithms.MlDsa44, BcAlgorithms.MlDsa65, BcAlgorithms.MlDsa87,
                                 BcAlgorithms.SlhDsa128s, BcAlgorithms.SlhDsa192s, BcAlgorithms.SlhDsa256s },
        PqTiers = new PqTiers(TierA: true, TierB: true, TierC: false),
    };
```

- [ ] **Step 6: Run → PASS.**

- [ ] **Step 7: Commit**

```bash
git add src/ScepTestClient.CryptoApi/PqTiers.cs src/ScepTestClient.CryptoApi/CryptoCapabilities.cs src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs tests/ScepTestClient.Tests/PqCapabilitiesTests.cs
git commit -m "Phase 4: advertise PQ algorithms and tiers (A/B yes, C no) via CryptoCapabilities"
```

---

## Task 5: BC provider tier A — ML-DSA/SLH-DSA key generation + PKCS#8 round-trip

**Goal:** `GenerateKey` produces ML-DSA / SLH-DSA keypairs; `ExportPrivateKeyPkcs8`/`ImportPrivateKeyPkcs8` round-trip them. Keep `BouncyCastleScepCrypto` readable by putting PQ specifics in a new `BcPqKeys` helper.

**Files:**
- Create: `src/ScepTestClient.Crypto.BouncyCastle/BcPqKeys.cs`
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcKey.cs` (allow a PQ keypair; `KeyPair` stays an `AsymmetricCipherKeyPair`)
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs` (`GenerateKey` branch; `ImportPrivateKeyPkcs8` PQ branch)
- Test: `tests/ScepTestClient.Tests/PqKeyGenTests.cs`

**Acceptance Criteria:**
- [ ] `GenerateKey(ml-dsa:65)` returns an `IScepKey` with `AlgorithmOid == 2.16.840.1.101.3.4.3.18`.
- [ ] `GenerateKey(slh-dsa:128s)` succeeds.
- [ ] PKCS#8 export then import yields a key with the same `AlgorithmOid` (re-export byte-identical where BC is deterministic).
- [ ] RSA keygen/export/import unchanged.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqKeyGenTests` → PASS

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqKeyGenTests.cs`:

```csharp
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqKeyGenTests {
    [Theory]
    [InlineData("ml-dsa:65", "2.16.840.1.101.3.4.3.18")]
    [InlineData("ml-dsa:87", "2.16.840.1.101.3.4.3.19")]
    [InlineData("slh-dsa:128s", "2.16.840.1.101.3.4.3.20")]
    public void Generates_pq_key(string key_spec, string expected_oid) {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse(key_spec, out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        Assert.Equal(expected_oid, key.AlgorithmOid);
    }

    [Fact]
    public void Pkcs8_roundtrip_ml_dsa() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        IScepKey imported;
        byte[] der;
        byte[] der2;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        Assert.True(crypto.ExportPrivateKeyPkcs8(key, out der, out error), error);
        Assert.True(crypto.ImportPrivateKeyPkcs8(der, out imported, out error), error);
        Assert.Equal(key.AlgorithmOid, imported.AlgorithmOid);
        Assert.True(crypto.ExportPrivateKeyPkcs8(imported, out der2, out error), error);
        Assert.Equal(der, der2);
    }
}
```

- [ ] **Step 2: Run → FAIL** (provider rejects non-RSA).

- [ ] **Step 3: Create `BcPqKeys.cs`** — keygen + OID mapping (BC names/namespaces arbitrated by the test):

```csharp
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Crypto.BouncyCastle;

internal static class BcPqKeys {
    // Returns true and sets pair/oid for an ML-DSA or SLH-DSA spec; false if spec is not PQ.
    public static bool TryGenerate(KeySpec spec, SecureRandom random, out AsymmetricCipherKeyPair pair, out string oid, out string error) {
        pair = null!;
        oid = string.Empty;
        error = string.Empty;

        if (spec.Algorithm.Equals("ML-DSA", StringComparison.OrdinalIgnoreCase)) {
            Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyPairGenerator generator;
            Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaParameters parameters;

            parameters = spec.Parameter switch {
                "44" => Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaParameters.ml_dsa_44,
                "65" => Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaParameters.ml_dsa_65,
                "87" => Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaParameters.ml_dsa_87,
                _ => null!,
            };
            if (parameters == null) { error = $"unsupported ML-DSA set '{spec.Parameter}'"; return false; }
            generator = new Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyPairGenerator();
            generator.Init(new Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyGenerationParameters(random, parameters));
            pair = generator.GenerateKeyPair();
            oid = "ML-DSA-" + spec.Parameter;
            return true;
        }

        if (spec.Algorithm.Equals("SLH-DSA", StringComparison.OrdinalIgnoreCase)) {
            Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaKeyPairGenerator generator;
            Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaParameters parameters;

            // Map "128s"/"192s"/"256s" to the SHA2 small SlhDsaParameters fields (verify names per BC 2.5.0).
            parameters = spec.Parameter switch {
                "128s" => Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaParameters.slh_dsa_sha2_128s,
                "192s" => Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaParameters.slh_dsa_sha2_192s,
                "256s" => Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaParameters.slh_dsa_sha2_256s,
                _ => null!,
            };
            if (parameters == null) { error = $"unsupported SLH-DSA set '{spec.Parameter}'"; return false; }
            generator = new Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaKeyPairGenerator();
            generator.Init(new Org.BouncyCastle.Pqc.Crypto.SlhDsa.SlhDsaKeyGenerationParameters(random, parameters));
            pair = generator.GenerateKeyPair();
            oid = "SLH-DSA-" + spec.Parameter;
            return true;
        }

        return false;
    }

    // Map an OID name back through the registry; resolves a PQ private key's friendly OID for re-import.
    public static string OidForName(string name) => Algorithms.OidFor(name) ?? name;

    public static bool IsPqOid(string oid) {
        AlgorithmKind? kind;

        kind = Algorithms.KindOf(oid);
        return kind == AlgorithmKind.Signature && oid != BcAlgorithms.Rsa;
    }
}
```

  > Note: `BcKey` stores `AlgorithmOid` as the OID string. `BcPqKeys.TryGenerate` returns the friendly name ("ML-DSA-65"); convert to OID with `Algorithms.OidFor(...)` at the `BcKey` construction site so `AlgorithmOid` is the OID (matches the RSA path which stores `BcAlgorithms.Rsa`).

- [ ] **Step 4: Branch `GenerateKey`** in `BouncyCastleScepCrypto.cs` (PQ first, then existing RSA path):

```csharp
    public bool GenerateKey(KeySpec spec, out IScepKey key, out string error) {
        RsaKeyPairGenerator generator;
        AsymmetricCipherKeyPair pair;
        AsymmetricCipherKeyPair pq_pair;
        string pq_oid;

        key = null!;
        error = string.Empty;

        if (BcPqKeys.TryGenerate(spec, _random, out pq_pair, out pq_oid, out error)) {
            key = new BcKey(pq_pair, Algorithms.OidFor(pq_oid)!, 0);
            return true;
        }
        if (!string.IsNullOrEmpty(error)) {
            return false;   // PQ algorithm recognized but parameter invalid
        }

        if (!spec.Algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase)) {
            error = $"provider does not support key algorithm '{spec.Algorithm}'";
            return false;
        }

        try {
            generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(_random, spec.Size));
            pair = generator.GenerateKeyPair();
            key = new BcKey(pair, BcAlgorithms.Rsa, spec.Size);
            return true;
        } catch (Exception ex) {
            error = $"RSA key generation failed: {ex.Message}";
            return false;
        }
    }
```

- [ ] **Step 5: PQ export/import.** `ExportPrivateKeyPkcs8` currently uses `PrivateKeyInfoFactory.CreatePrivateKeyInfo` — for PQ keys use `PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo` when `BcPqKeys.IsPqOid(bc_key.AlgorithmOid)`. In `ImportPrivateKeyPkcs8`, `PrivateKeyFactory.CreateKey(der)` returns a PQ key-params instance for PQ PKCS#8; detect non-`RsaPrivateCrtKeyParameters` and, if it is an ML-DSA/SLH-DSA private key params type, wrap it in a `BcKey` with the right OID (derive via the key's parameter set; the round-trip test arbitrates the exact type/name). Add a `BcPqKeys.TryImport(priv, out pair, out oid)` helper to keep the provider clean.

- [ ] **Step 6: Run → PASS** (adjust BC names/namespaces until the round-trip test is green; report any deviation from the names above).

- [ ] **Step 7: Commit**

```bash
git add src/ScepTestClient.Crypto.BouncyCastle/BcPqKeys.cs src/ScepTestClient.Crypto.BouncyCastle/BcKey.cs src/ScepTestClient.Crypto.BouncyCastle/BouncyCastleScepCrypto.cs tests/ScepTestClient.Tests/PqKeyGenTests.cs
git commit -m "Phase 4: tier A — ML-DSA/SLH-DSA key generation + PKCS#8 round-trip"
```

---

## Task 6: BC provider tier A — PQ CSR encode (SPKI + PQ signature)

**Goal:** `EncodeCsr` emits a PKCS#10 with a PQ `SubjectPublicKeyInfo` and a PQ signature when the subject key is ML-DSA/SLH-DSA; the produced CSR parses and its signature verifies.

**Files:**
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs`
- Test: `tests/ScepTestClient.Tests/PqCsrTests.cs`

**Acceptance Criteria:**
- [ ] An ML-DSA-65 CSR can be built; re-parsing it (`new Pkcs10CertificationRequest(der)`) succeeds and `.Verify()` returns true.
- [ ] The CSR's SubjectPublicKeyInfo algorithm OID is the ML-DSA OID.
- [ ] Challenge password and SAN/SID/EKU extensions still emit on a PQ CSR (reuse `BuildExtensions`).
- [ ] RSA CSR path unchanged (existing `BcCsrTests` green).

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqCsrTests` → PASS (and `BcCsrTests` green)

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqCsrTests.cs`:

```csharp
using Org.BouncyCastle.Pkcs;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqCsrTests {
    [Fact]
    public void Ml_dsa_csr_parses_and_verifies() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=pq-test", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        Assert.Contains("2.16.840.1.101.3.4.3.18",
            parsed.GetCertificationRequestInfo().SubjectPublicKeyInfo.Algorithm.Algorithm.Id);
    }
}
```

- [ ] **Step 2: Run → FAIL** (`Asn1SignatureFactory("SHA256WITHRSA", pqKey)` cannot sign a PQ key).

- [ ] **Step 3: Branch `BcCsrBuilder.Build`** on PQ vs RSA. For PQ, build the request with the PQ `SubjectPublicKeyInfo` (`PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key.KeyPair.Public)`) and a PQ `ISignatureFactory`. Preferred call: `new Asn1SignatureFactory("ML-DSA-65", key.KeyPair.Private, random)`; if 2.5.0 does not map that name, implement a minimal `ISignatureFactory` over `MLDsaSigner`/`SlhDsaSigner`. The 4-arg `Pkcs10CertificationRequest(signer, subject, pubKey, attrs)` accepts a PQ `AsymmetricKeyParameter` public key. Reuse `BuildExtensions(csr)` unchanged. Sketch:

```csharp
    public static byte[] Build(Pkcs10 csr, BcKey key) {
        X509Name subject;
        Org.BouncyCastle.Crypto.ISignatureFactory signer;
        List<Asn1Encodable> attributes;
        X509Extensions extensions;
        Asn1Set attribute_set;
        Pkcs10CertificationRequest request;

        subject = new X509Name(csr.Subject);
        signer = BcPqKeys.IsPqOid(key.AlgorithmOid)
            ? BcPqKeys.SignatureFactory(key)                  // PQ signer (round-trip test arbitrates)
            : new Asn1SignatureFactory("SHA256WITHRSA", key.KeyPair.Private);
        attributes = new List<Asn1Encodable>();

        if (!string.IsNullOrEmpty(csr.ChallengePassword)) {
            attributes.Add(new AttributePkcs(new DerObjectIdentifier(ChallengePasswordOid), new DerSet(new DerPrintableString(csr.ChallengePassword))));
        }

        extensions = BuildExtensions(csr);
        if (extensions is not null) {
            attributes.Add(new AttributePkcs(new DerObjectIdentifier(ExtensionRequestOid), new DerSet(extensions)));
        }

        attribute_set = new DerSet(attributes.ToArray());
        request = new Pkcs10CertificationRequest(signer, subject, key.KeyPair.Public, attribute_set);
        return request.GetEncoded();
    }
```

  Add `BcPqKeys.SignatureFactory(BcKey)` returning the appropriate `Asn1SignatureFactory` (or custom factory). If the friendly-name `Asn1SignatureFactory("ML-DSA-65", priv, random)` path works, inline it and skip the helper.

- [ ] **Step 4: Run → PASS** (adjust until the PQ CSR verifies; report the exact working signer construction).

- [ ] **Step 5: Commit**

```bash
git add src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs tests/ScepTestClient.Tests/PqCsrTests.cs
git commit -m "Phase 4: tier A — encode PQ CSR with PQ SubjectPublicKeyInfo and signature"
```

---

## Task 7: Tier B — catalyst alt-key (subjectAltPublicKeyInfo) + --alt-key-spec

**Goal:** Carry an optional alt public key into the CSR as the `subjectAltPublicKeyInfo` extension (OID `2.5.29.72`), expose it through `Pkcs10.AltKey`, `EnrollRequest.AltKey`, `ScepRequestBuilder.AltKey`, and the `--alt-key-spec` CLI flag. Record a `ConformanceNote` that the alt-signature value is not computed by the built-in provider.

**Files:**
- Modify: `src/ScepTestClient.CryptoApi/Pkcs10.cs` (add `AltKey`)
- Modify: `src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs` (emit the extension)
- Modify: `src/ScepTestClient.Core/EnrollRequest.cs` (`AltKey`), `src/ScepTestClient.Core/ScepRequestBuilder.cs` (`.AltKey`), `src/ScepTestClient.Core/ScepClient.cs` (thread `EnrollRequest.AltKey` → `Pkcs10.AltKey`)
- Modify: `src/ScepTestClient.Cli/CommandRouter.cs` (`--alt-key-spec` in `RunGet`)
- Test: `tests/ScepTestClient.Tests/AltKeyCsrTests.cs`

**Acceptance Criteria:**
- [ ] `Pkcs10.AltKey` is a nullable `IScepKey` defaulting to null (existing callers unaffected).
- [ ] An RSA-primary CSR built with an ML-DSA `AltKey` contains the `2.5.29.72` extension whose value is the ML-DSA SubjectPublicKeyInfo.
- [ ] When no `AltKey` is set, no `2.5.29.72` extension is emitted (existing CSRs byte-shape unchanged aside from existing behavior).
- [ ] CLI: `enroll <server> --subject CN=x --key-spec rsa:2048 --alt-key-spec ml-dsa:65` generates the alt key and passes it through (covered by a router-level unit on `EnrollRequest` wiring, no live server needed).

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter AltKeyCsrTests` → PASS

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/AltKeyCsrTests.cs`:

```csharp
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class AltKeyCsrTests {
    [Fact]
    public void Alt_key_emits_subject_alt_public_key_info() {
        BouncyCastleScepCrypto crypto;
        KeySpec rsa_spec;
        KeySpec alt_spec;
        IScepKey rsa_key;
        IScepKey alt_key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;
        Org.BouncyCastle.Asn1.X509.X509Extensions exts;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("rsa:2048", out rsa_spec, out error), error);
        Assert.True(KeySpec.Parse("ml-dsa:65", out alt_spec, out error), error);
        Assert.True(crypto.GenerateKey(rsa_spec, out rsa_key, out error), error);
        Assert.True(crypto.GenerateKey(alt_spec, out alt_key, out error), error);

        csr = new Pkcs10 { Key = rsa_key, AltKey = alt_key };
        csr.SetSubject("CN=catalyst", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        exts = ExtensionsFrom(parsed);
        Assert.NotNull(exts.GetExtension(new DerObjectIdentifier("2.5.29.72")));
    }

    private static Org.BouncyCastle.Asn1.X509.X509Extensions ExtensionsFrom(Pkcs10CertificationRequest req) {
        // Pull the extensionRequest attribute (1.2.840.113549.1.9.14) and parse X509Extensions.
        foreach (Org.BouncyCastle.Asn1.Pkcs.AttributePkcs attr in req.GetAttributes()) {
            if (attr.AttrType.Id == "1.2.840.113549.1.9.14") {
                return Org.BouncyCastle.Asn1.X509.X509Extensions.GetInstance(attr.AttrValues[0]);
            }
        }
        throw new System.Exception("no extensionRequest attribute");
    }
}
```

  > If `GetAttributes()` is not the exact accessor in BC 2.5.0, use `GetCertificationRequestInfo().Attributes` and `AttributePkcs.GetInstance(enc)` (per the Phase-3 challenge-password read pattern in the BC reference memory). The test arbitrates.

- [ ] **Step 2: Run → FAIL** (no `AltKey`; no extension).

- [ ] **Step 3: Add `Pkcs10.AltKey`:**

```csharp
    public IScepKey? AltKey { get; set; }
```

- [ ] **Step 4: Emit the extension** in `BcCsrBuilder.BuildExtensions` (before the `return`): when `csr.AltKey is BcKey alt_bc`, add the alt SPKI as the `2.5.29.72` extension:

```csharp
        if (csr.AltKey is BcKey alt_bc) {
            Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo alt_spki;

            alt_spki = Org.BouncyCastle.Pqc.Crypto.Utilities.PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(alt_bc.KeyPair.Public);
            gen.AddExtension(new DerObjectIdentifier("2.5.29.72"), false, alt_spki);
            any = true;
        }
```

  > `PqcSubjectPublicKeyInfoFactory` handles PQ alt keys; for a classical alt key use `SubjectPublicKeyInfoFactory`. The built-in provider does **not** compute `altSignatureAlgorithm`/`altSignatureValue` (bleeding-edge). Record this once at the call path: in `BouncyCastleScepCrypto.EncodeCsr`, when `csr.AltKey != null`, the provider cannot add a ConformanceNote to a stateless `Pkcs10` cleanly — instead document it in code comments here and surface the limitation through the analysis doc + `crypto info` (Task 10). (No ConformanceNotes channel on `EncodeCsr`; keep it a documented limitation.)

- [ ] **Step 5: Thread the alt key through Core + CLI.** Add `EnrollRequest.AltKey` (`IScepKey?`), set `Pkcs10.AltKey` wherever `ScepClient` builds the inner CSR from an `EnrollRequest` (find the build site in `ScepClient.cs`), add `ScepRequestBuilder.AltKey(IScepKey)` + assign to the built `Pkcs10`. In `CommandRouter.RunGet`, parse `--alt-key-spec`, generate the alt key via `crypto.GenerateKey`, set `request.AltKey`.

- [ ] **Step 6: Run → PASS.** Run the full suite (alt-key is additive; nothing else should change).

- [ ] **Step 7: Commit**

```bash
git add src/ScepTestClient.CryptoApi/Pkcs10.cs src/ScepTestClient.Crypto.BouncyCastle/BcCsrBuilder.cs src/ScepTestClient.Core/EnrollRequest.cs src/ScepTestClient.Core/ScepRequestBuilder.cs src/ScepTestClient.Core/ScepClient.cs src/ScepTestClient.Cli/CommandRouter.cs tests/ScepTestClient.Tests/AltKeyCsrTests.cs
git commit -m "Phase 4: tier B — catalyst alt-key via subjectAltPublicKeyInfo + --alt-key-spec"
```

---

## Task 8: Capabilities drive opinion (CuttingEdge) + servers suggest

**Goal:** Add PQ classification to `SecurityOpinion` (`ClassifySignature` → `CuttingEdge`) and make `servers suggest` emit a PQ enroll command when the loaded provider supports tier A.

**Files:**
- Modify: `src/ScepTestClient.Core/Testing/SecurityOpinion.cs` (new `ClassifySignature`)
- Modify: `src/ScepTestClient.Core/Testing/ServerSuggest.cs` (overload taking provider `CryptoCapabilities`)
- Modify: `src/ScepTestClient.Cli/CommandRouter.cs` (`RunServersSuggest` passes provider caps + prints PQ posture)
- Test: `tests/ScepTestClient.Tests/PqOpinionSuggestTests.cs`

**Acceptance Criteria:**
- [ ] `SecurityOpinion.ClassifySignature("ML-DSA-65")` and `("SLH-DSA-128s")` → `AlgorithmPosture.CuttingEdge`; `("RSA")` → `Modern`; unknown → `Unknown`.
- [ ] `ServerSuggest.For(server_id, scepCaps, cryptoCaps)` includes a `--key-spec ml-dsa:65` line when `cryptoCaps.PqTiers.TierA` is true; the existing classical lines remain.
- [ ] The existing `ServerSuggest.For(server_id, scepCaps)` signature still exists (back-compat) — delegates with default (no-PQ) caps.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqOpinionSuggestTests` → PASS (and `SecurityOpinionTests`/`CliScenarioSuggestTests` green)

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqOpinionSuggestTests.cs`:

```csharp
using System.Linq;
using ScepTestClient.Core.Protocol;
using ScepTestClient.Core.Testing;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqOpinionSuggestTests {
    [Theory]
    [InlineData("ML-DSA-65", AlgorithmPosture.CuttingEdge)]
    [InlineData("SLH-DSA-128s", AlgorithmPosture.CuttingEdge)]
    [InlineData("RSA", AlgorithmPosture.Modern)]
    [InlineData("bogus", AlgorithmPosture.Unknown)]
    public void Classifies_signatures(string name, AlgorithmPosture expected) {
        Assert.Equal(expected, SecurityOpinion.ClassifySignature(name));
    }

    [Fact]
    public void Suggest_includes_pq_when_provider_supports_tier_a() {
        ScepCapabilities scep_caps;
        CryptoCapabilities crypto_caps;
        System.Collections.Generic.IReadOnlyList<string> lines;

        scep_caps = ScepCapabilities.Parse("SHA-256\nAES\n");
        crypto_caps = new CryptoCapabilities { PqTiers = new PqTiers(TierA: true) };
        lines = ServerSuggest.For("srv", scep_caps, crypto_caps);
        Assert.Contains(lines, l => l.Contains("ml-dsa:65"));
        Assert.Contains(lines, l => l.Contains("--digest SHA-256"));
    }
}
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Add `ClassifySignature`** to `SecurityOpinion.cs`:

```csharp
    public static AlgorithmPosture ClassifySignature(string name) {
        string upper;

        upper = (name ?? string.Empty).ToUpperInvariant();
        if (upper.StartsWith("ML-DSA") || upper.StartsWith("SLH-DSA") || upper.StartsWith("ML-KEM")) {
            return AlgorithmPosture.CuttingEdge;
        }
        if (upper == "RSA") { return AlgorithmPosture.Modern; }
        return AlgorithmPosture.Unknown;
    }
```

- [ ] **Step 4: Add the `ServerSuggest.For` overload** taking `CryptoCapabilities`; keep the old one delegating with `new CryptoCapabilities()`:

```csharp
    public static IReadOnlyList<string> For(string server_id, ScepCapabilities caps) =>
        For(server_id, caps, new CryptoCapabilities());

    public static IReadOnlyList<string> For(string server_id, ScepCapabilities caps, CryptoCapabilities crypto_caps) {
        // ... existing classical digest/cipher cross-product (unchanged) ...
        if (crypto_caps.PqTiers.TierA) {
            lines.Add($"sceptest enroll {server_id} --subject \"CN=test\" --key-spec ml-dsa:65 --digest {digests[0]} --cipher {ciphers[0]}");
        }
        return lines;
    }
```

- [ ] **Step 5: Wire the CLI** — in `RunServersSuggest`, load the provider, pass `client.Crypto.Capabilities` to `ServerSuggest.For`, and add a posture line using `ClassifySignature` when `client.Crypto.Capabilities.PqTiers.TierA`.

- [ ] **Step 6: Run → PASS.**

- [ ] **Step 7: Commit**

```bash
git add src/ScepTestClient.Core/Testing/SecurityOpinion.cs src/ScepTestClient.Core/Testing/ServerSuggest.cs src/ScepTestClient.Cli/CommandRouter.cs tests/ScepTestClient.Tests/PqOpinionSuggestTests.cs
git commit -m "Phase 4: capabilities drive opinion (CuttingEdge) and PQ servers-suggest"
```

---

## Task 9: Empirical PQ probe

**Goal:** Add a `ProbePq` step to `RunProbe` that attempts an ML-DSA enroll (when the provider supports tier A) and reports the result, since GetCACaps has no PQ keyword (any success is a FINDING).

**Files:**
- Modify: `src/ScepTestClient.Core/Testing/TestEngine.cs`
- Test: `tests/ScepTestClient.Tests/PqProbeTests.cs`
- (Maybe) Modify: `tests/ScepTestClient.Tests/Fakes/TestCa.cs` only if needed to observe a PQ attempt gracefully.

**Acceptance Criteria:**
- [ ] `RunProbe` produces a result row named like `"probe ML-DSA enrollment"`.
- [ ] When the provider supports tier A but the server cannot issue PQ, the row is `Failed` (or `Finding` if it unexpectedly succeeds) — never throws.
- [ ] The probe is skipped with a clear `why` when `client.Crypto.Capabilities.PqTiers.TierA` is false.
- [ ] Existing probe rows (digest/POST/GetNextCACert) unchanged.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter PqProbeTests` → PASS (and `TestEngineModesTests` green)

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/PqProbeTests.cs` — spin up `FakeScepServer`/`TestCa` (as in `TestEngineModesTests`), run `RunProbe`, assert a PQ row exists and the run did not throw:

```csharp
using System.Linq;
using ScepTestClient.Core.Testing;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqProbeTests {
    [Fact]
    public async System.Threading.Tasks.Task Probe_includes_pq_row() {
        // Arrange: FakeScepServer + TestCa + ScepClient (mirror TestEngineModesTests setup).
        // Act:
        // TestReport report = new TestEngine().RunProbe(client);
        // Assert:
        // Assert.Contains(report.Results, r => r.Name.Contains("ML-DSA"));
        await System.Threading.Tasks.Task.CompletedTask;
        Assert.True(true);   // replace with the real arrange/act/assert mirroring TestEngineModesTests
    }
}
```

  > Implementer: copy the exact server/client construction from `TestEngineModesTests.cs` (it already builds a live `FakeScepServer` + `ScepClient`). Replace the placeholder body with a real assertion on the PQ row.

- [ ] **Step 2: Run → FAIL** (no PQ row).

- [ ] **Step 3: Add `ProbePq`** to `TestEngine.cs` and call it from `RunProbe` after `ProbeGetNextCa`:

```csharp
    private static void ProbePq(TestReport report, ScepClient client) {
        Stopwatch sw;
        bool worked;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        if (!client.Crypto.Capabilities.PqTiers.TierA) {
            report.Results.Add(new CheckResult("probe ML-DSA enrollment", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "loaded provider does not implement PQ tier A", "RFC 8894 (no PQ keyword) / spec §14", System.TimeSpan.Zero));
            return;
        }

        sw = Stopwatch.StartNew();
        worked = false;
        try {
            ca_result = ResolveCaCert(client);
            if (ca_result.IsOk) {
                worked = SubmitEnrollWithKeySpec(client, ca_result.Value, "ml-dsa:65", "SHA-256");
            }
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (worked) {
            outcome = CheckOutcome.Finding;
            why = "ML-DSA enrollment succeeded though GetCACaps advertises no PQ capability (under-advertised / PQ-capable CA)";
        } else {
            outcome = CheckOutcome.Failed;
            why = "ML-DSA enrollment was not accepted (expected against a classical-only CA)";
        }
        report.Results.Add(new CheckResult("probe ML-DSA enrollment", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "spec §14 (empirical PQ probe)", sw.Elapsed));
    }
```

  Add a `SubmitEnrollWithKeySpec(client, ca_cert, key_spec, digest)` helper (generalize the existing `SubmitEnrollWithDigest`, which hardcodes `rsa:2048`) — or add a `KeySpec` parameter to it and update its one caller.

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit**

```bash
git add src/ScepTestClient.Core/Testing/TestEngine.cs tests/ScepTestClient.Tests/PqProbeTests.cs
git commit -m "Phase 4: empirical PQ probe (ML-DSA enroll → PASSED/FINDING/FAILED)"
```

---

## Task 10: `crypto info` / `crypto list` CLI

**Goal:** Add the `crypto` command. `crypto list` prints the loaded provider's algorithms grouped by kind (friendly names); `crypto info` prints the provider DLL path and PQ tier support.

**Files:**
- Create: `src/ScepTestClient.Cli/CryptoCommand.cs`
- Modify: `src/ScepTestClient.Cli/CommandRouter.cs` (route `crypto`, add to usage)
- Test: `tests/ScepTestClient.Tests/CryptoCommandTests.cs`

**Acceptance Criteria:**
- [ ] `crypto list` output contains `ML-DSA-65` (under signatures/keys) and `ML-KEM-768` (under KEM) and `SHA-256` (digests).
- [ ] `crypto info` output reports `Tier A: yes`, `Tier B: yes`, `Tier C: no` and the provider source ("built-in" when default).
- [ ] Unknown `crypto <verb>` prints usage and returns non-zero.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter CryptoCommandTests` → PASS

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/CryptoCommandTests.cs`:

```csharp
using System.IO;
using ScepTestClient.Cli;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class CryptoCommandTests {
    [Fact]
    public void Crypto_list_shows_pq() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "list" }, Path.GetTempPath(), output);
        Assert.Equal(0, code);
        Assert.Contains("ML-DSA-65", output.ToString());
        Assert.Contains("ML-KEM-768", output.ToString());
        Assert.Contains("SHA-256", output.ToString());
    }

    [Fact]
    public void Crypto_info_shows_tiers() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "info" }, Path.GetTempPath(), output);
        Assert.Equal(0, code);
        Assert.Contains("Tier A: yes", output.ToString());
        Assert.Contains("Tier C: no", output.ToString());
    }
}
```

- [ ] **Step 2: Run → FAIL** (no `crypto` route).

- [ ] **Step 3: Create `CryptoCommand.cs`** — load the provider via the same resolver as the rest of the CLI (Task 11 introduces `ResolveProviderPath`; for now call `ScepCrypto.Load(null, ...)`, and Task 11 swaps it to the resolver), group `Capabilities` by kind using `Algorithms.NameFor(oid) ?? oid`:

```csharp
using System.IO;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Cli;

internal static class CryptoCommand {
    public static int Run(string[] args, string data_root, TextWriter output) {
        string verb;
        IScepCrypto crypto;
        string error;

        if (args.Length < 2) { output.WriteLine("usage: crypto <info|list>"); return 2; }
        verb = args[1];

        if (ScepCrypto.Load(null, out crypto, out error) != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {error}");
            return 1;
        }

        switch (verb) {
            case "list": return List(crypto, output);
            case "info": return Info(crypto, output);
            default: output.WriteLine("usage: crypto <info|list>"); return 2;
        }
    }

    private static int List(IScepCrypto crypto, TextWriter output) {
        PrintGroup(output, "Digests", crypto.Capabilities.Digests);
        PrintGroup(output, "Signatures", crypto.Capabilities.Signatures);
        PrintGroup(output, "ContentEncryption", crypto.Capabilities.ContentEncryption);
        PrintGroup(output, "KeyTransport", crypto.Capabilities.KeyTransport);
        PrintGroup(output, "KEM", crypto.Capabilities.Kem);
        PrintGroup(output, "AsymmetricKeys", crypto.Capabilities.AsymmetricKeys);
        return 0;
    }

    private static int Info(IScepCrypto crypto, TextWriter output) {
        output.WriteLine("Provider: built-in (BouncyCastle)");
        output.WriteLine($"Tier A: {(crypto.Capabilities.PqTiers.TierA ? "yes" : "no")}");
        output.WriteLine($"Tier B: {(crypto.Capabilities.PqTiers.TierB ? "yes" : "no")}");
        output.WriteLine($"Tier C: {(crypto.Capabilities.PqTiers.TierC ? "yes" : "no")}  (ML-KEM CMS envelope — provider seam; BouncyCastle 2.5.0 has no CMS KEM recipient)");
        return 0;
    }

    private static void PrintGroup(TextWriter output, string title, System.Collections.Generic.IReadOnlyCollection<string> oids) {
        System.Collections.Generic.List<string> names;

        names = new System.Collections.Generic.List<string>();
        foreach (string oid in oids) { names.Add(Algorithms.NameFor(oid) ?? oid); }
        output.WriteLine($"{title}: {string.Join(", ", names)}");
    }
}
```

- [ ] **Step 4: Route `crypto`** in `CommandRouter.RunInternal` (`case "crypto": return CryptoCommand.Run(args, data_root, output);`) and add two usage lines.

- [ ] **Step 5: Run → PASS.**

- [ ] **Step 6: Commit**

```bash
git add src/ScepTestClient.Cli/CryptoCommand.cs src/ScepTestClient.Cli/CommandRouter.cs tests/ScepTestClient.Tests/CryptoCommandTests.cs
git commit -m "Phase 4: crypto info / crypto list CLI"
```

---

## Task 11: `--crypto-provider` flag + config wiring at all load sites

**Goal:** Resolve the provider DLL path from `--crypto-provider <path>` (else `ClientConfig.CryptoProviderPath`, else built-in) and thread it into **every** `ScepCrypto.Load` call site; add `config set <key> <value>` so the provider path can be persisted.

**Files:**
- Modify: `src/ScepTestClient.Cli/CommandRouter.cs` (add `ResolveProviderPath`; use it in `RunGetCaCaps`, `RunGet`, `BuildClient`, `RunServersSuggest`; add `config set`)
- Modify: `src/ScepTestClient.Cli/CryptoCommand.cs` (accept a resolved provider path)
- Modify: `src/ScepTestClient.Core/Storage/ClientConfig.cs` (only if a setter helper is wanted; the props already exist)
- Test: `tests/ScepTestClient.Tests/CryptoProviderFlagTests.cs`

**Acceptance Criteria:**
- [ ] `ResolveProviderPath` returns the `--crypto-provider` value when present; else `ClientConfig.CryptoProviderPath`; else null.
- [ ] `config set crypto-provider <path>` persists to `config.json`; `config show` then displays it.
- [ ] All CLI commands that load crypto pass the resolved path (a passing build + a unit on `ResolveProviderPath` + a `config set`/`config show` round-trip suffice).
- [ ] A bogus `--crypto-provider /nope.dll` yields the existing "crypto provider DLL not found" error path (non-zero exit), not a crash.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter CryptoProviderFlagTests` → PASS (and `CliRouterTests`/`CliRouterPhase2Tests` green)

**Steps:**

- [ ] **Step 1: Write the failing test** `tests/ScepTestClient.Tests/CryptoProviderFlagTests.cs`:

```csharp
using System.IO;
using ScepTestClient.Cli;
using ScepTestClient.Core.Storage;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class CryptoProviderFlagTests {
    [Fact]
    public void Config_set_persists_crypto_provider() {
        string root;
        StringWriter output;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        output = new StringWriter();
        Assert.Equal(0, CommandRouter.Run(new[] { "config", "set", "crypto-provider", "/tmp/p.dll" }, root, output));

        output = new StringWriter();
        Assert.Equal(0, CommandRouter.Run(new[] { "config", "show" }, root, output));
        Assert.Contains("/tmp/p.dll", output.ToString());
    }

    [Fact]
    public void Bogus_provider_path_errors_cleanly() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "list", "--crypto-provider", "/nope.dll" }, Path.GetTempPath(), output);
        Assert.NotEqual(0, code);
        Assert.Contains("not found", output.ToString());
    }
}
```

- [ ] **Step 2: Run → FAIL** (`config set` unrecognized; `--crypto-provider` ignored).

- [ ] **Step 3: Add `ResolveProviderPath`** to `CommandRouter`:

```csharp
    private static string? ResolveProviderPath(string[] args, string data_root) {
        string? flag;
        ClientConfig config;

        flag = Opt(args, "--crypto-provider");
        if (!string.IsNullOrWhiteSpace(flag)) { return flag; }

        config = ClientConfig.Load(data_root);
        return config.CryptoProviderPath;
    }
```

- [ ] **Step 4: Swap every `ScepCrypto.Load(null, ...)`** in `RunGetCaCaps`, `RunGet`, `BuildClient`, and `CryptoCommand.Run` to `ScepCrypto.Load(ResolveProviderPath(args, data_root), ...)` (pass `args`/`data_root` into `CryptoCommand.Run`).

- [ ] **Step 5: Add `config set`** in `RunConfig`:

```csharp
        if (args.Length >= 4 && args[1] == "set") {
            ClientConfig config;
            string key;
            string value;

            config = ClientConfig.Load(data_root);
            key = args[2];
            value = args[3];
            switch (key) {
                case "crypto-provider": config.CryptoProviderPath = value; break;
                case "key-spec": config.KeySpec = value; break;
                case "min-rsa-bits": if (int.TryParse(value, out int bits)) { config.MinRsaKeyBits = bits; } break;
                default: output.WriteLine($"unknown config key '{key}'"); return 2;
            }
            config.Save(data_root);
            output.WriteLine($"set {key} = {value}");
            return 0;
        }
```

  Add `config set` + `config set-root` (if not already) to usage.

- [ ] **Step 6: Run → PASS.**

- [ ] **Step 7: Commit**

```bash
git add src/ScepTestClient.Cli/CommandRouter.cs src/ScepTestClient.Cli/CryptoCommand.cs src/ScepTestClient.Core/Storage/ClientConfig.cs tests/ScepTestClient.Tests/CryptoProviderFlagTests.cs
git commit -m "Phase 4: --crypto-provider flag + config set, threaded to all crypto load sites"
```

---

## Task 12: External-provider ALC loading hardening

**Goal:** Harden `ScepCrypto.Load` + `ProviderLoadContext`: reject ambiguous providers (>1 `IScepCrypto` impl) with a clear error, confirm the contract type identity is shared across the ALC boundary, and prove a path-loaded provider works end to end.

**Files:**
- Modify: `src/ScepTestClient.Core/ScepCrypto.cs` (ambiguity check; clearer errors)
- Modify: `src/ScepTestClient.Core/ProviderLoadContext.cs` (keep CryptoApi shared; resolve provider deps; optional `Unload` note)
- Test: `tests/ScepTestClient.Tests/ProviderLoadTests.cs` (extend)

**Acceptance Criteria:**
- [ ] Loading the built-in BC provider DLL **by explicit path** (the copy in the test output dir) via `ScepCrypto.Load(path, ...)` succeeds and the returned `crypto.Capabilities` is the shared-contract type (no `InvalidCastException`; `crypto is IScepCrypto` true).
- [ ] A path with **no** `IScepCrypto` impl → `ProviderError` with "no IScepCrypto implementation".
- [ ] When an assembly exposes **more than one** `IScepCrypto` impl, `Load` returns `ProviderError` "multiple IScepCrypto implementations" (deterministic, not first-wins).
- [ ] The contract type identity is shared: a key generated by the path-loaded provider is accepted by `EncodeCsr` of the same instance (round-trip) — proves single `IScepKey`/`IScepCrypto` `Type` identity.

**Verify:** `dotnet test tests/ScepTestClient.Tests --filter ProviderLoad` → PASS

**Steps:**

- [ ] **Step 1: Write/extend the failing test** in `tests/ScepTestClient.Tests/ProviderLoadTests.cs`:

```csharp
[Fact]
public void Loads_provider_by_explicit_path_with_shared_contract() {
    string dll;
    IScepCrypto crypto;
    string error;
    KeySpec spec;
    IScepKey key;
    Pkcs10 csr;
    byte[] der;

    dll = Path.Combine(AppContext.BaseDirectory, "ScepTestClient.Crypto.BouncyCastle.dll");
    Assert.Equal(ScepClientResult.Ok, ScepCrypto.Load(dll, out crypto, out error));
    Assert.True(crypto is IScepCrypto);
    Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
    Assert.True(crypto.GenerateKey(spec, out key, out error), error);   // shared IScepKey type identity
    csr = new Pkcs10 { Key = key };
    csr.SetSubject("CN=alc", out error);
    Assert.True(crypto.EncodeCsr(csr, out der, out error), error);
}
```

  (Use the existing namespaces/usings already in `ProviderLoadTests.cs`.)

- [ ] **Step 2: Run → FAIL** if the explicit-path load path or ambiguity check is missing; otherwise confirm the new assertions surface the gap.

- [ ] **Step 3: Harden `ScepCrypto.Load`** — replace `FirstOrDefault` with an explicit count so >1 impl is an error:

```csharp
            System.Collections.Generic.List<Type> impls;

            impls = assembly.GetTypes()
                .Where(t => typeof(IScepCrypto).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface)
                .ToList();
            if (impls.Count == 0) {
                error = $"no IScepCrypto implementation found in {Path.GetFileName(path)}";
                return ScepClientResult.ProviderError;
            }
            if (impls.Count > 1) {
                error = $"multiple IScepCrypto implementations found in {Path.GetFileName(path)} ({impls.Count})";
                return ScepClientResult.ProviderError;
            }
            impl_type = impls[0];
```

- [ ] **Step 4:** Confirm `ProviderLoadContext.Load` already returns `null` for `ScepTestClient.CryptoApi` (it does, `:17`) so the contract stays shared. Add a short XML/inline comment documenting that this is the single-Type-identity guarantee. (No functional change unless the test reveals a gap with `GetTypes()` throwing `ReflectionTypeLoadException` — if so, catch it and surface `LoaderExceptions[0].Message`.)

- [ ] **Step 5: Run → PASS.**

- [ ] **Step 6: Commit**

```bash
git add src/ScepTestClient.Core/ScepCrypto.cs src/ScepTestClient.Core/ProviderLoadContext.cs tests/ScepTestClient.Tests/ProviderLoadTests.cs
git commit -m "Phase 4: harden external-provider ALC loading (ambiguity check + shared-contract proof)"
```

---

## Final verification (after all tasks)

- [ ] `dotnet build` → **0 warnings** (the standing gate).
- [ ] `dotnet test` → all green (100 prior ScepTestClient tests + the new PQ tests + 67 IntuneSimulator tests).
- [ ] `dotnet run --project src/ScepTestClient.Cli -- crypto list` shows ML-DSA/ML-KEM; `crypto info` shows Tier A/B yes, C no.
- [ ] Confirm no `IScepCrypto` interface signature changed (diff `src/ScepTestClient.CryptoApi/IScepCrypto.cs` — only the comment may differ, if at all).
- [ ] Re-sync the co-located `.tasks.json` statuses to `completed`.

Then run **superpowers-extended-cc:finishing-a-development-branch**. PR via SmartGit (merge commit, granular commits preserved — no squash).

## Self-review notes (author)

- Spec coverage: §14 tiers A/B/C → Tasks 5/6 (A), 7 (B), 4+10 (C advertised-only, documented); §3.3 OID registry → Task 2; §3.4 capabilities driving opinion/probe/suggest → Tasks 4/8/9; §3.5 future seam (provider hardening) → Tasks 11/12; §17 row 4 (`crypto info/list`, `--crypto-provider`/config, empirical PQ probe) → Tasks 9/10/11/12. PQ-1 paper validation (§14, Phase-1 carry-over) → Task 1.
- Type consistency: `PqTiers` record (TierA/TierB/TierC) used identically in CryptoCapabilities, provider, opinion/suggest, probe, crypto info. `KeySpec.Parameter` introduced Task 3, consumed Tasks 5/6. `Pkcs10.AltKey` introduced Task 7, consumed in BcCsrBuilder same task. `ClassifySignature` introduced + consumed Task 8.
- Deferred §13 subject-mismatch test: explicitly kept deferred (header) — not silently dropped.
