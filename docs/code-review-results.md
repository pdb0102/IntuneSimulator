# SCEPwright code-review results

Whole-codebase review (2026-06-21), produced by 6 parallel review agents (5 by area + 1 cross-cutting) plus a spec-conformance pass. Findings are **grouped into work-blocks** so each block can be handed to a single fix-agent. Every finding cites a verified `file:line`.

> **STATUS (2026-06-22): ALL BLOCKS RESOLVED.** Decisions implemented (CA-key encryption, spec amendment, Ekus/CodecOptions wired up). Block 0 (`.editorconfig` re-scope + IVT), 1 (braces), 2 (declare-at-top), 3 (dead members), 4 (comments), 5 (renames), 6 (access), 7 (XML docs on every public API), 9 (CLAUDE.md note) all done across ~8 commits; 373 tests green, 0 warnings throughout. Block 8 spec items were amended in the design spec.

**Scope of the house style** (no `var`; declare-locals-at-top then blank line then assignments; same-line K&R braces; **always `{ }`**; snake_case locals/params/private-fields; PascalCase members; avoid needless LINQ; parenthesize compound conditionals; crypto only via `IScepCrypto`): applies to `src/ScepWright.*` + `tests/ScepWright.Tests`. **`IntuneSimulator` is intentionally exempt** (modern `var`/LINQ idioms) — no style findings were raised against it.

## How to use this file
Blocks are ordered by recommended sequence. Suggested fix-agent dispatch:
- **Block 0 first** (it re-enables machine enforcement, which then catches Block 1/2 mechanically).
- **Blocks 1, 2, 4, 7** are mechanical/bulk — one agent each (Block 7 may split by project).
- **Block 3 (functional) and Block 8 (spec)** need *decisions* before coding — flagged inline; don't auto-fix.
- Dependency: **Block 6 (access)** depends on the `InternalsVisibleTo` change in Block 0.

Severity: **must** = real defect / enforcement gap · **should** = clear improvement · **nit** = polish.

---

## ✅ Decisions — RESOLVED & IMPLEMENTED (2026-06-21)
1. **CA private key encryption — DONE.** `scepca` now has `--encrypt-keys` + `--key-pass` (+ `$SCEPWRIGHT_CA_KEY_PASS`); encrypted PKCS#8 (PBES2/PBKDF2-HMAC-SHA256/AES-256) for CA+RA keys; passphrase precedence flag>env>interactive-prompt>fail-on-non-interactive. New `CaKeyProtection`/`CaKeyPassphrase`. TDD + OpenSSL-verified + stable-CA-across-restart. (Was Block 8.)
2. **Standalone server — spec AMENDED.** §6/§7 of the design spec now document the lib/host split and the deliberately-standalone server (no `StoreRole`, no Core ref). No code change. (Was Block 8.)
3. **`Ekus` + `CodecOptions` — WIRED UP.** `BcCsrBuilder` emits the EKU extension; new repeatable `--eku` flag; scepca honors the CSR's requested EKU (OpenSSL-verified). `BcPkiMessage.Decode` now honors `CodecOptions` (Strict enforces signature + non-legacy digest; Skip/AllowLegacy/Lenient relax). TDD; `LenientParsing` callers unchanged. (Was Block 3-functional.)

---

## Block 0 — Enforcement & build config  *(must; do first)*
Fixing the glob means a `dotnet format`/analyzer pass will mechanically surface most of Block 1/2.
- `[CONFIG] .editorconfig:19 — must — the house-style glob targets the pre-rename paths {src/ScepTestClient.CryptoApi, …ScepTestClient.Crypto.BouncyCastle, …ScepTestClient.Core, …ScepTestClient.Cli, tests/ScepTestClient.Tests}/**.cs — none exist, so brace/snake_case/no-LINQ rules are NOT enforced; only the repo-wide [*.cs] no-var rule applies. Fix: rewrite the glob to {src/ScepWright.Crypto, src/ScepWright.Crypto.BouncyCastle, src/ScepWright.Core, src/ScepWright.Client, src/ScepWright.Server, src/ScepWright.Server.Host, src/ScepWright.Dispatcher, tests/ScepWright.Tests}/**.cs. Also update the line-16 comment ("scoped to ScepTestClient").`
- `[CONFIG] src/ScepWright.Server/ScepWright.Server.csproj — should — it's the only consumer project WITHOUT <InternalsVisibleTo Include="ScepWright.Tests"/> (Crypto, Core, Crypto.BouncyCastle, Server.Host all have it). That forces a large test-only surface in ScepCa to be public (see Block 6). Fix: add the IVT, then demote per Block 6.`

## Block 1 — Always-braces violations (B)  *(must; tiny, mechanical)*
- `[B] src/ScepWright.Core/Transport/ScepHttpTransport.cs:22 — must — `if (message.Length > 0) query += …;` unbraced. Fix: brace.`
- `[B] src/ScepWright.Core/Transport/ScepHttpTransport.cs:79 — must — `if (!resp.IsSuccessStatusCode) return …;` unbraced. Fix: brace.`
- `[B] src/ScepWright.Core/Transport/ScepHttpTransport.cs:84 — must — same, unbraced return. Fix: brace.`
- `[B] src/ScepWright.Core/Protocol/ScepCapabilities.cs:30 — must — `if (kw.Length == 0) continue;` unbraced. Fix: brace.`
- `[B] src/ScepWright.Client/Program.cs:14 — must — `if (args[i] == name) return args[i + 1];` unbraced. Fix: brace.`
(Crypto, Server, Tests: zero brace violations — verified.)

## Block 2 — Declare-locals-at-top (A, rule 2)  *(should; manual pass — analyzers won't auto-fix this convention)*
Locals declared mid-block (after executable statements) or inline in `if`/`out`, instead of unassigned-at-top then blank line then assignments.
**ScepWright.Core:**
- `[A] src/ScepWright.Core/ScepRequestBuilder.cs:155 — should — `IScepKey signer_key;` declared mid-block. Also the PQ branch at 165-168 interleaves decls+logic.`
- `[A] src/ScepWright.Core/ScepClient.cs:668,709 — should — inline `out X509Certificate2 recipient, out string select_error` in the if. Also 297 (BuildRenewMessage) and 799-801 (PQ branch interleaved).`
- `[A] src/ScepWright.Core/Testing/ComplianceEngine.cs:43 / TestEngine.cs:50,86 — nit — `System.Action<X509Certificate2> capture = …` declared-and-assigned mid-method.`
**ScepWright.Client (CommandRouter is the bulk — ~17 sites):**
- `[A] src/ScepWright.Client/CommandRouter.cs:161-163 — should — locals declared mid-block; same pattern at 466-468, 515/520, 569-570, 665-666, 722-723, 735, 772-773, 877-878, 1092-1093, 1458-1462, 1467-1469, 1540-1541, 1576-1578, 1599-1603, 1614-1615, 1713-1718.`
- `[A] src/ScepWright.Client/Program.cs:13 — nit — `for (int i = …)` inline counter vs the repo's `int i;` then `for (i=…)`.`
- `[A] src/ScepWright.Client/CommandRouter.cs:247,667,672,709,774,1462 — nit — single-letter foreach vars (s/c/o/r); rename to descriptive snake_case. ConsoleTrace.cs:11 param `e`.`
**ScepWright.Server:**
- `[A] src/ScepWright.Server/ScepCa.cs:804 (inline `mlkem_priv`), 834 (inline `out found`), 872-873 (tx_a/n_a mid-block); ServerCli.cs:92 (inline `out int p`). — should/nit.`
**ScepWright.Crypto.BouncyCastle:**
- `[A] src/ScepWright.Crypto.BouncyCastle/BcPkiMessage.cs:203 — should — `string fail_info_str` declared-and-assigned mid-`if`; hoist (match pki_status_str above).`
**tests/ScepWright.Tests (mostly one file):**
- `[A] tests/ScepWright.Tests/CliRouterPhase2Tests.cs — should — ~10 mid-block decls: 83,89,189,195,230,260,280,286,287,310,316,363,392.`
- `[A] tests/ScepWright.Tests/EncryptedKeyTests.cs:86; CliTestCommandTests.cs:21,126; BcCrlDecodeTests.cs:32; ScepClientTests.cs:79 — should/nit — hoist to top decl block.`
**Optional (rule 7, LINQ in reporting):** `JsonReport.cs:20 / MarkdownReport.cs:23 / ConsoleSummary.cs:23` use `.Select/.Count` projections — borderline; leave unless consistency is wanted.

## Block 3 — Unused / ignored members & inputs (C)  *(mixed: 2 functional → decide; rest are dead-code removal)*
**Functional (input accepted then ignored — decide: wire up or remove):**
- `[C] src/ScepWright.Crypto/Pkcs10.cs:13 (Ekus) — should — set by ScepClient/ScepRequestBuilder but BcCsrBuilder.BuildExtensions (src/ScepWright.Crypto.BouncyCastle/BcCsrBuilder.cs:49) emits only SANs, never an ExtendedKeyUsage extension → requested EKUs silently dropped. Fix: emit EKU, or remove Ekus.`
- `[C] src/ScepWright.Crypto/CodecOptions.cs:7-8 + BcPkiMessage.cs:134 — should — SkipSignatureVerification/AllowLegacyAlgorithms never honored; Decode ignores its `options` param entirely (only LenientParsing is ever passed, and it's a no-op). Fix: honor the flags in Decode, or drop them.`
**Dead members (remove, or wire/justify):**
- `[C] src/ScepWright.Core/ScepClient.cs:21-22,34,57 — should — RenewalCertificate/RenewalKey set only by the cert+key Create overload and never read; that overload has no callers. Remove both props + the overload. (See Block 6 F.)`
- `[C] src/ScepWright.Core/Protocol/ScepCapabilities.cs:15 — should — ScepStandard parsed but never read.`
- `[C] src/ScepWright.Crypto/KeySpec.cs:14 — should — Raw set in ctor, never read.`
- `[C] src/ScepWright.Crypto/Pkcs10.cs:14 (TemplateName, never read) + :27 (instance Encode, uncalled) — should/nit.`
- `[C] src/ScepWright.Crypto/ScepClientResult.cs:11 — nit — StorageError enum member unreferenced.`
- `[C] src/ScepWright.Core/ScepServerApp.cs:24 (CaCapsBody setter never assigned → make init-only/const) , :25 (Profiles getter unread) — should/nit.` *(file is src/ScepWright.Server/ScepServerApp.cs)*
- `[C] src/ScepWright.Core/ScepClient.cs:449,460,471,482 — nit — GetCert/GetCrl (sync+async) `out IScepKey signer_key` never read → use `out _`.`
- `[C] IntuneSimulator (exempt from style, but dead members still count): Auth/ClientCredentialValidator.cs:12 (clientId param unused), Scep/ScepModels.cs:46 (ScepErrorCodes.All unread), Failure/FailureFlowEngine.cs:19 (TimeoutDelayMs setter never invoked), SimulatorState.cs:68 (RevocationQueue unread). — should/nit.`

## Block 4 — Comment cleanup (D)  *(nit/should; judgment + mechanical)*
Remove comments that (a) explain a *change*/edit-reasoning, (b) restate the code, (c) are stale. **Strip backlog tags** (`#NN`, `persona-backlog #NN`, `FOLLOWUPS #N`, `Reviewer blocker:`) but KEEP the behavioral sentence after them.
**src/:**
- `[D] src/ScepWright.Core/Storage/CertStore.cs:17 — should — "Phase 1 overload — unchanged signature, now delegates…" is edit-history. Reduce to a plain purpose line.`
- `[D] backlog-tag strips: ScepClient.cs:24-25 (#14), Recipients/RecipientHealth.cs:9 (#21), Testing/{CoverageMatrixDoc.cs:6, IssuedCert.cs:3, TestReport.cs:10, TestEngine.cs:49,85} (#14/#15), Testing/ServerSuggest.cs:59 (#30), Client/CommandRouter.cs:160 (#22), :741 (#21). — nit — drop the tag, keep the rationale.`
- `[D] src/ScepWright.Client/CommandRouter.cs:611 ("Phase-2 operations" dev-phase banner), :872 (parenthetical edit-note) — nit — rename/drop.`
- `[D] src/ScepWright.Server/ScepCa.cs:647 ("Success (existing issue path)" → "// Success."), :122-123 (trim "(see Issue())" back-ref), ScepServerApp.cs:67 ("all 11" → "every profile"). — nit.`
- `[D] src/ScepWright.Crypto/IScepCrypto.cs:6-13 (PQ-readiness "validated 2026-06-19" changelog block → move to design docs), Crypto.BouncyCastle/BouncyCastleScepCrypto.cs:113 (restates FaultDirectives), BcEnvelope.cs:9-10 (speculative "design spec §3.5 could later own this"). — nit.`
**tests/ (~24 sites, all backlog-tag prefixes — strip lead, keep the note):**
- `[D] ComplianceEngineTests.cs:43,76,107,128,150,171,193; CliRouterPhase2Tests.cs:11,23,99,123,150,344,421; TestEngineModesTests.cs:46,67,88,140; CliTestCommandTests.cs:34,64; PqRenewalTests.cs:14,58; RecipientSelectorTests.cs:107; ServerSuggestTests.cs:25; TextReportTests.cs:27,61; TransportErrorTests.cs:6; RecipientHealthTests.cs:10. — nit.`
**KEEP (do NOT flag):** crypto/protocol/RFC notes — BcPkiMessage nonce handling, KEM/RFC 9629, PBES2/PKCS#12-MAC, EC named-curve, AES-key-unwrap, `CanEnvelopeTo`/recipient-selection footguns, transient-RSA-transport, NDES, the fixed-CA-serial design note, the `< /dev/null`/Interactive console-hang test note, PqSubjectEnrollTests PQ-transport note.

## Block 5 — Naming consistency (E)  *(should/nit; cross-cutting)*
- `[E] src/ScepWright.Core/Reporting/ConsoleSummary.cs:7 — should — sibling emitters are `*Report.Emit(TestReport)` (Json/Markdown/JUnit/Trx) but this is `ConsoleSummary.Format(…)` — different suffix AND verb. Fix: rename to ConsoleReport.Emit (or at least .Emit); update call sites CommandRouter.cs:1071,1114,1318 + TextReportTests.cs:32,95.`
- `[E] src/ScepWright.Crypto.BouncyCastle/BcKemEnvelope.cs:28 — nit — KEM path is EncryptCbc while the RSA/EC sibling is BcEnvelope.Build. Fix: rename to BuildCbc for the parallel "produce EnvelopedData" op.`
- `[E] src/ScepWright.Server/ScepCa.cs:319 — nit — GetCaCertBundleDer vs the parallel Build*CertRep/Build*CrlRep family. Fix: rename BuildCaCertBundleDer.`
- `[E] tests/ScepWright.Tests — nit — client-builder helper has 3 names: BuildClientFor (6 files), BuildClientWithStore (TestEngineModesTests.cs:238), BuildClient (CoverageMatrixTests.cs:86). Fix: standardize on BuildClientFor / BuildClientForWithStore. (See Block "DUP" below.)`
- `[E] src/ScepWright.Client/CommandRouter.cs:1248 — nit — ReadRepeated vs the sibling option helpers Opt/HasFlag/CountFlag. Fix: rename OptAll/OptMany.`
- `[E] src/ScepWright.Core/ScepRequestBuilder.cs:200,223 — nit — BuildIssuerSerialMessage/BuildPollMessage param `subject_key` is really a transient key for GetCert/GetCrl/CertPoll. Fix: rename `transient_key`.`

## Block 6 — Access modifiers (F)  *(should/nit; depends on Block 0 IVT)*
- `[F] src/ScepWright.Server/ScepCa.cs — should — after adding the IVT (Block 0), demote test-only-public methods to internal: BuildSuccessCertRep/BuildPendingCertRep/BuildFailureCertRep/BuildSuccessCrlRep (426/443/467/481), Issue/IssueExpired (369/396), VerifyOuterSignature/ReadSigningTime/InnerCsrParses (742/757/770), GenerateCrl (456). Keep PeekMessageType public (used by ScepServerApp:198).`
- `[F] src/ScepWright.Core/ScepClient.cs:34,57 — should — the cert+key Create overload is public but unused → remove (with Block 3 C) or mark internal.`
- `[F] src/ScepWright.Server/ScepServerApp.cs:24 (CaCapsBody → init-only), :25 (Profiles → remove/justify). — should/nit.`
- `[F] src/ScepWright.Dispatcher/DispatcherCli.cs:76 — should — UnifiedHelp is public but only called internally. Fix: private static.`
- `[F] src/ScepWright.Crypto.BouncyCastle/BcKemEnvelope.cs:96 — nit — EncryptGcm/Decrypt/DecryptGcm are "ported for completeness; not used by SCEP", reachable only from KemEnvelopeTests. Fix: make internal (class already internal).`
- `[F] IntuneSimulator (public→internal, used only intra-Core): Scep/ScepModels.cs:44 (ScepErrorCodes), Auth/BearerCheck.cs:6, UrlHelpers.cs:5, SimResults.cs:12, Control/ConfigInfo.cs:6. — nit.`

## Block 7 — XML documentation on public APIs (G)  *(should/nit; large — split by project)*
Add terse Microsoft-style `/// <summary>` to public types/methods/properties (not private/internal, not test code). Many already have a leading `//` that can be promoted to `///`. **No public type in the ScepWright tree currently has XML docs.**
- **7a Crypto contract (highest value):** `src/ScepWright.Crypto/` — IScepCrypto (12 methods; document the result-bool + out value/out error convention and the `legacy` flag), PkiMessage (~25 props; distinguish request-input vs decode-output), Algorithms/AlgorithmEntry (+OidFor/NameFor/KindOf), KeySpec.Parse (+the rsa/ec/ml-dsa/slh-dsa/ml-kem grammar), and ~11 more public types/enums (CryptoCapabilities, ScepResult, ScepClientResult, CodecOptions, FaultDirectives, ConformanceNote, PqTiers, IScepKey, FailInfo, MessageType, PkiStatus).
- **7b Core:** ScepClient (+ all public methods), EnrollRequest/EnrollOutcome/RenewRequest, ServerConfig, ScepCapabilities, RecipientSelector/RecipientSelection/RecipientFinding/RecipientKind/RecipientStrategy, the report emitters, Testing (TestEngine/ComplianceEngine/ScenarioRunner/JamfSimulator/SecurityOpinion/ServerSuggest/CoverageMatrixDoc + CheckOutcome/FaultKind), ScepCrypto, Storage (CertStore/ServerRegistry/UseRecordLog/DataRoot/Redaction/ClientConfig), Challenge/IChallengeSource, ScepTraceEvent, RenewalVariant.
- **7c Client/Dispatcher:** CommandRouter (type + Run/HelpUse/HelpTest), PassphrasePrompt (+Interactive/Resolve), DispatcherCli (+Run).
- **7d Server:** ScepCa, ScepServerApp, ServerCli — public surface (Create*/Issue/Handle*/Persist/LoadFrom etc.).
- **7e IntuneSimulator (lower priority):** the Map* endpoint classes (AadEndpoints/GraphEndpoints/ScepEndpoints/RevocationEndpoints/ChallengeEndpoints/ControlEndpoints), enums (FailureFlowMode/FailureMode), Host/CommandLineOptions HostConfig.

## Block 8 — Spec conformance (H)  *(needs decisions; see top callout)*
- `[H] StoreRole — should — spec §7/§5a mandate StoreRole {Client,Server} to select a subtree under one shared root; it does not exist (zero hits). Server reimplements root resolution in ServerCli.cs:135-148 (ResolveCaRoot), duplicating DataRoot.Resolve. Decide: build StoreRole + route server storage through Core, OR amend spec.`
- `[H] src/ScepWright.Server/ScepWright.Server.csproj — should — spec §6/§7 say Server references Core (storage centralized); it has ZERO Core refs (deliberate per memory). Reconcile spec text with the as-built standalone server.`
- `[H] src/ScepWright.Server.Host/ServerCli.cs — should — spec §7 says scepca supports --encrypt-keys/--key-pass; it doesn't. The CA private key is written PLAINTEXT (ScepCa.Persist → ca.key.pkcs8). Decide: implement encrypted-at-rest for the CA key, or record a deferral.`
- `[H] src/ScepWright.Server/ScepCa.cs:61-77 — nit — §7 layout is ca/<profile>/{ca.pem, ca.key.pkcs8[.enc], caps.json}; actual is ca.cert.der + ca.key.pkcs8 (plaintext) + sigalg.txt + ra.* and no caps.json. Reconcile filenames/format in the spec or code.`
- `[H] §6 project mapping — nit — spec lists ScepWright.Server as the scepca exe; as built it's split into ScepWright.Server (lib) + ScepWright.Server.Host (exe), and the dispatcher references the Host. Update §6 to document the lib/host split (no code change).`

## Block 9 — Duplicate logic & convention notes  *(nit)*
- `[DUP] tests/ScepWright.Tests/CoverageMatrixTests.cs:86 vs TestEngineModesTests.cs:238 — should — near-identical client+store builder copies; hoist one shared test helper. (The deliberately-duplicated server KEM-decrypt vs BcKemEnvelope was compared and is NOT diverged — leave it.)`
- `[CONVENTION] src/ScepWright.Crypto/IScepCrypto.cs — nit — the contract's 11 methods return `bool` while ScepClient.Create returns the ScepClientResult enum; both use out value/out error. Deliberate, internally consistent. Fix: note in CLAUDE.md that the crypto contract uses bool-discriminated results so "result enum" isn't read as a violation.`

---

## Counts (approx, deduped)
- Block 1 (braces, must): 5 · Block 2 (declare-at-top): ~45 sites across 6 files · Block 3 (unused/ignored): ~16 (2 functional) · Block 4 (comments): ~40 (mostly tag-strips) · Block 5 (naming): 6 · Block 6 (access): ~15 · Block 7 (XML docs): pervasive — every public type · Block 8 (spec): 5 · Block 9: 2.
- **Verified clean:** no `var` in the ScepWright tree; no Allman braces; no casing violations; no crypto-library leakage into the dep-free `ScepWright.Crypto` contract; no control-flow-throws crossing the contract boundary; the standalone server's KEM-decrypt copy matches the client's.
