# Test Personas & Review Playbook

A repeatable, persona-driven external review process for the SCEPwright suite (`scepclient`, `scepca`, `scepwright`, `IntuneSimulator.Host`). Each persona is a fresh, isolated agent that *uses* the tool the way a particular real-world user would, and reports what frustrates, confuses, or breaks. Run it after any substantial code change to get unbiased, end-to-end feedback that ordinary unit tests don't surface.

The two halves of this document:
- **Part 1 — How to re-run the review** (the process, mechanics, and a dispatch template).
- **Part 2 — The personas** (who they are, what they attack, and how they're isolated).

---

# Part 1 — How to re-run the review

## When to use it
- After a feature, refactor, or bug-fix batch that touches user-facing behavior (CLI, server responses, reports, crypto, docs).
- Before calling a release "clean."
- It complements `dotnet test`; it does **not** replace it. Always run the unit suite first.

## Core principles
1. **Fresh, unbiased agents.** Each persona is a separate sub-agent with no access to prior findings or this session's history. Don't tell a re-run persona what it found last time — what it *stops* complaining about is the signal that a fix landed.
2. **Reproduce, don't trust.** The orchestrator (you) independently re-runs the highest-severity claims before reporting them as fact. Agents make mistakes (and honestly retract them); verify the load-bearing ones.
3. **Isolation is mandatory.** Agents run concurrently — each gets its own port(s), `$SCEPWRIGHT_HOME`, and `--data-dir`. No shared state.
4. **Use built binaries, not `dotnet run`.** Publish once to a shared folder; parallel `dotnet run`/`dotnet build` race on `bin/obj`. Publishing also matches how a real user installs the tool.

## Step 0 — Build the tools fresh (orchestrator, once per run)
Publish each tool into one shared folder (mirrors the real `scepwright-<rid>.zip` layout — the BouncyCastle provider must sit beside the exe). Run the publishes **sequentially** (a shared output dir + parallel publish can race):

```bash
cd <repo>
rm -rf /tmp/scepwright-dist /tmp/intune-dist
dotnet publish src/ScepWright.Client      -c Release -o /tmp/scepwright-dist --nologo -v q
dotnet publish src/ScepWright.Server.Host -c Release -o /tmp/scepwright-dist --nologo -v q
dotnet publish src/ScepWright.Dispatcher  -c Release -o /tmp/scepwright-dist --nologo -v q
dotnet publish src/IntuneSimulator.Host   -c Release -o /tmp/intune-dist     --nologo -v q
# smoke test
/tmp/scepwright-dist/scepwright help >/dev/null && echo "scep OK"
test -f /tmp/intune-dist/IntuneSimulator.Host && echo "intune OK"
```
Note the warning count (the suite builds 0-warning; regressions matter) and run `dotnet test` to confirm the unit suite is green before dispatching anyone.

## Step 1 — Choose scope
Pick the personas whose surface your change touched (see the mapping table in Part 2). For a broad release review, run all eight. For a targeted change, run the 2–4 relevant ones plus the **focused adversarial pass** on the new code.

## Step 2 — Dispatch personas in parallel
Send all chosen personas in a single batch so they run concurrently. Each agent prompt must contain:
- **Persona brief** (Part 2) — who they are and what they attack. Stay in character.
- **Tool location** — `/tmp/scepwright-dist/` (and `/tmp/intune-dist/` for Kevin). "Run like a downloaded user: `cd /tmp/scepwright-dist && ./scepclient …`."
- **Docs** — point at `README.md` + the relevant `docs/*.md`; tell them to read what their persona would.
- **Isolation block** (mandatory) — their unique port(s), `export SCEPWRIGHT_HOME=/tmp/persona-<name>`, `--data-dir /tmp/persona-<name>-ca`, "start clean: `rm -rf` those first," "kill every server you start," "do NOT modify `src/`," "scratch in `/tmp`."
- **Exit-code hygiene** — "to read an exit code, run the command then `echo $?` on its OWN line; never `cmd | tail; echo $?` (that reads tail's exit)." This caused multiple false alarms; always include it.
- **Return format** — (1) one-paragraph in-character summary, (2) findings list with severity `[blocker/major/minor/polish]` + exact command + observed output, (3) what genuinely worked (credit), (4) the persona's verdict, (5) top-3 fixes.

## Step 3 — Orchestrator verifies the top claims
After the agents return, **independently reproduce** every blocker and high-severity finding (and any claim that contradicts a "this is fixed" assumption) with your own commands. Use `openssl` to verify cert claims (algorithm, chain, SAN, validity, timestamps), `python3 -m json.tool` / `xmllint` for report integrity. Mark verified findings with a ★. Agents retract their own false positives sometimes — don't propagate the ones you can't reproduce.

## Step 4 — Synthesize into the backlog
Fold all findings into `docs/persona-backlog.md`:
- **Deduplicate** across personas; list every reviewer who raised it in `[brackets]`.
- **Severity-sort**: blocker → high → medium → low → nitpick/polish.
- **Checkbox per item** (`- [ ]`) so the fixer can track; `[x]` done, `[~]` partial/by-design.
- **Provenance tag** once fixed: `code` / `docs` / `code+docs` / `code+by-design` / `by-design`.
- Keep self-retracted items OUT (note them so nobody re-chases artifacts).

## Round modes (escalation ladder)
Run these as the code matures:

1. **Standard round** — the 8 personas as written. Use on a rough/early build.
2. **Nit-pick round** — same personas, plus an instruction: *"This build is mature; be an exacting nitpicker — surface even small issues; if you can't break it, say so and name what still keeps it short of perfect."* Use once the obvious issues are gone, to harvest polish.
3. **Independent verification** — one fresh, skeptical agent re-runs the *backlog itself* black-box ("don't trust the DONE notes; reproduce each item; flag anything claimed-fixed-but-not-fixed"). Confirms a fix batch before sign-off.
4. **Focused adversarial pass** — 2–3 white-box agents whose only job is to **break the newly-added code** (not re-walk persona scripts). Give them the changed files/symbols and tell them to hunt for crashes (HTTP 500, stack traces), wrong results (false pass/fail, silent corruption/downgrade), and robustness/edge failures. This is where new code's new bugs hide — the broad personas and the verifier won't find them. Split by area, e.g.:
   - **A** — the riskiest behavioral change (e.g. renewal / recipient resolution).
   - **B** — the test/report engine (baseline controls, new checks, footprint, exit codes, report integrity).
   - **C** — issuance/CLI surface (new flags, SAN, diagnose, error paths, encoding).

**The full loop we ran this session:** standard rounds → fixes → nit-pick round → fixes → independent verification → focused adversarial pass → backlog. Diminishing returns set in fast on the broad rounds; once they're quiet, the adversarial pass on *new* code is the higher-value spend.

## Mechanics & gotchas (learned the hard way)
- **Isolation table** — keep ports/dirs disjoint (see Part 2). The default server data-dir is `~/.scepwright/ca` (shared!) — always pass `--data-dir` and set `$SCEPWRIGHT_HOME` per agent.
- **`scepca` default port is 8090** — keep your own verification off the personas' ranges.
- **Pre-build, don't let agents `dotnet run`** — avoids `bin/obj` races between concurrent agents.
- **Background servers:** start `scepca` backgrounded; the agent must `pkill` what it started before finishing. Orchestrator does a final sweep `pkill -f "scepca --port <p>"` and `rm -rf /tmp/persona-* /tmp/adv-* /tmp/verify-*`.
- **`timeout` is not on macOS** — use background+`sleep`+`pkill` instead.
- **False positives are normal** — expect ~1 self-retraction per few agents (pipe/exit-code artifacts, stale-build confusion, wrong scenario schema). That's why Step 3 exists.
- **Tell adversarial agents they may read `src/`** (white-box) but must prove findings empirically against the running binary; persona agents stay black-box.

## Dispatch template (fill the brackets)
```
You are doing a [first-impressions UX | adversarial robustness] evaluation of [tool],
fully in character as [PERSONA]. Behave EXACTLY as this person would. Don't be a helpful
expert; be the persona. [NIT-PICK MODE: this build is mature — be exacting; if you can't
break it, say so and name what still falls short.]

## The tool (installed like a download)
/tmp/scepwright-dist/ → ./scepclient ./scepca ./scepwright  (Kevin: /tmp/intune-dist/IntuneSimulator.Host)
Run as a downloaded user: cd /tmp/scepwright-dist && ./scepclient ...
Docs in repo <repo>: README.md, docs/<relevant>.md — read what your persona would.

## Isolation (MANDATORY — concurrent evaluators)
Start clean: rm -rf /tmp/persona-<name> /tmp/persona-<name>-ca
Client: export SCEPWRIGHT_HOME=/tmp/persona-<name>
Server (if used): ./scepca --port <PORT> --data-dir /tmp/persona-<name>-ca ... (backgrounded; ONLY your port[s])
Kill every server you start. Do NOT modify src/. Scratch in /tmp.
Exit codes: run cmd, THEN `echo $?` on its OWN line (never `cmd | tail; echo $?`).

## YOUR PERSONA: <brief from Part 2 — goals, knowledge level, what to attack>

## Return
1. One-paragraph in-character summary.
2. Findings — severity [blocker/major/minor/polish], exact command, observed output.
3. What genuinely worked (credit).
4. The persona's verdict.
5. Top 3 fixes for this persona.
Concrete output only. Return findings, not narration. Clean up before finishing.
```

---

# Part 2 — The personas

Nine user-facing personas plus the two meta-roles. Each maps to a tool surface — pick by what your change touched.

## Surface → persona map
| If your change touches… | Run these personas |
|---|---|
| `scepclient get/enroll/renew`, key storage, export | Niles, John (if PQ), Sam (if security) |
| Compliance suite (`test`/`run`), reports, exit codes, CI | Kyle, Sam |
| `diagnose`, `getcacaps/getcacert`, `servers suggest` | Roz, Sam |
| `scepca` server, profiles, persistence, fault injection | Lola, John (if PQ) |
| Post-quantum (ML-DSA/SLH-DSA/ML-KEM), recipient enveloping | John |
| IntuneSimulator (AAD/Graph/Intune chain) | Kevin |
| Docs, help text, packaging, flag hygiene, security framing | Peter |
| Public API (`ScepWright.Core`/`.Crypto`), `IScepCrypto` provider (`--crypto-provider`), XML docs, NuGet/packaging | Ivan |
| Any new code (always) | the **focused adversarial pass** |

## Isolation assignments
| Persona | `$SCEPWRIGHT_HOME` | scepca port(s) | data-dir |
|---|---|---|---|
| Niles | `/tmp/persona-niles` | 8111 | `/tmp/persona-niles-ca` |
| Kyle | `/tmp/persona-kyle` | 8112 (+8122, 8132) | `/tmp/persona-kyle-ca*` |
| Roz | `/tmp/persona-roz` | 8113 (+8123, 8133) | `/tmp/persona-roz-ca*` |
| Lola | `/tmp/persona-lola` | 8114 (+8124) | `/tmp/persona-lola-ca*` |
| Peter | `/tmp/persona-peter` | 8115 | `/tmp/persona-peter-ca` |
| John | `/tmp/persona-john` | 8116 (+8126) | `/tmp/persona-john-ca*` |
| Kevin | `/tmp/persona-kevin` | scepca 8117; IntuneSim `--http-port 8181 --https-port 8543` | `/tmp/persona-kevin/ca` |
| Sam | `/tmp/persona-sam` | 8118 (+8128) | `/tmp/persona-sam-ca*` |
| Ivan | `/tmp/persona-ivan` | 8119 | `/tmp/persona-ivan-ca` |
| Independent verifier | `/tmp/verify-home` | 8201–8204; IntuneSim 8281/8643 | `/tmp/verify-ca*` |
| Adversarial A/B/C | `/tmp/adv-a` / `-b` / `-c` | 8211–8213 / 8221–8223 / 8231–8233 | `/tmp/adv-{a,b,c}-ca*` |

---

## Niles — the reluctant end-user
**Who:** A non-crypto person who just needs a certificate so some *other* software works. His IT guy gave him a SCEP URL and a challenge password and said "run this." He knows private keys are sensitive, so he wants his **encrypted** — but he doesn't know PEM/DER/PKCS#8 or hidden `~/.scepwright` folders.
**Surface:** `scepclient` `servers add` → `get`/`enroll` (with `--encrypt-keys`) → finding the files → coming back months later to `certs list`/`renew`.
**What he attacks:** Does the tool tell him *where his cert and key files are*? Is the obvious command safe by default? Can he find and renew a cert later having forgotten everything? Does it ever assume knowledge he lacks?
**Stand-in server:** his own `scepca --challenge` (pretend it's the corporate SCEP server).
**Verdict style:** "Would Niles keep using this, or go back to bugging IT?"

## Kyle — the QA release-gate engineer
**Who:** QA at a company that *sells* a SCEP server (with NDES). He wants `scepclient` wired into Jenkins as a hard gate proving RFC 8894 compliance. He relies on the tool's "fully tests a server" promise — he does **not** know the RFC well enough to hand-author the tests.
**Surface:** `test probe/lifecycle/full`, `run <scenario.json>`, `--report-format junit/trx/json/md`, `--fail-on-findings`, exit codes, NDES (`--ndes`, scepca `--ndes-user/--ndes-password`), the coverage matrix.
**What he attacks:** Is coverage real and *documented* (so he can justify trust)? Are exit codes CI-usable (does a finding/failure actually fail the build, or exit 0)? Are machine-readable reports complete and accurate? Can the suite exercise a challenge/NDES-protected CA — and does it fail loudly if misconfigured rather than silent-green?
**Verdict style:** "Would he gate the Jenkins pipeline on it — fully, partially, or no?"

## Roz — the JAMF support agent
**Who:** Customer-support agent at a SCEP-server vendor. Customers configure the product with RA/CA certs and enroll via JAMF; JAMF fails with a vague error. She wants to tell a customer "download SCEPwright, run ONE command, paste me the output" so *she* can spot the misconfig. It must be easy for a non-expert and informative for her.
**Surface:** `diagnose`, `getcacaps`, `getcacert`, `test probe`, `servers suggest`, `--jamf-max-wait`.
**What she attacks:** Is there a quick read-only "what's wrong" command? Does it reveal RA/CA cert details (subject, KeyUsage, validity, thumbprint) so she can confirm the right cert was selected? Against a *misconfigured* server (restricted `--caps`, signing-only / EC / ML-KEM recipient, `--pending`), does the output name the problem in language a customer can paste and she can interpret?
**Verdict style:** "Would she put this in a support email to a frustrated customer?"

## Lola — the independent dev needing a test server
**Who:** Solo dev embedding a SCEP client in her own app; she needs a local SCEP **test server** to develop against. She cares about `scepca` as a dev fixture.
**Surface:** `scepca` stand-up, `--export-ca`, profiles at `/scep/<profile>`, persistence across restarts, fault injection (`--pending`, `--challenge`), `openssl verify` of issued leaves.
**What she attacks:** How fast to stand up? Can her app **trust** the CA — does `--export-ca` produce a cert that `openssl verify` accepts for the leaves it issues (RSA/EC/PQ)? Does the CA persist byte-identically across restarts so her trust store stays valid? Are profiles discoverable/documented? Do `--pending`/`--challenge` return realistic responses for her error handling?
**Verdict style:** "Would she use `scepca` as her test server?"

## Peter — the grumpy tool-approval gatekeeper
**Who:** Approves which tools land on the company's "approved" list. Technical, deeply skeptical, default REJECT. He rejects for *any* of: spelling/grammar in help or docs; a documented example that fails when copy-pasted verbatim; quirky/inconsistent syntax; an advertised flag that does nothing; help-vs-behavior or doc-vs-tool mismatch; an enum flag that accepts garbage; a displayed cert field that disagrees with `openssl`; weak crypto / a fake security control; missing or odd LICENSE.
**Surface:** all help text, every README/doc example (run verbatim), flag hygiene (misspelled/fake/enum-garbage), `min-rsa-bits` enforcement, cert-field accuracy vs `openssl`, error paths (clean vs stack-trace), LICENSE, UNTRUSTED-CA framing, secrets-on-cmdline.
**What he produces:** a numbered **rejection report** — every strike with exact command/quote, grudging credits, and a final `APPROVE / APPROVE WITH CONDITIONS / REJECT` with the single most damaging strike.

## John — the post-quantum migration engineer
**Who:** Enterprise crypto/PKI engineer leading a PQ migration. Expert in FIPS 203/204/205, KEMRecipientInfo (RFC 9629), composite/hybrid. Skeptical of "PQ-ready" marketing; verifies everything at the byte level with `openssl` 3.6+.
**Surface:** `crypto info`/`crypto list`; PQ enrollment against scepca PQ profiles (`mldsa-*`, `slhdsa-rsa`, `mlkem-encrypt`); ML-KEM enveloping (RFC 9629); `--alt-key-spec`; PQ **lifecycle** (renew/GetCRL); the transient-RSA-transport-key behavior.
**What he attacks:** Are ML-DSA (44/65/87), SLH-DSA (all 6), ML-KEM (512/768/1024) genuinely real (openssl: signature *and* public-key algorithm, chain to a PQ CA — not RSA in costume)? Is ML-KEM enveloping a real `id-smime-ori-kem` KEMRecipientInfo? Does PQ **renew/CRL** complete (no HTTP 500 / downgrade)? Is `--alt-key-spec` honest about being non-conformant? Are guardrails correct (ML-KEM rejected as a signing key; signature-only CA can't envelope)?
**Verdict style:** "Trust it for PQ-migration testing — fully, partially, or no?"

## Kevin — the SCEP vendor validating Intune integration
**Who:** Senior engineer whose product *is* a SCEP server with Microsoft Intune integration (MSAL/AAD auth → Graph service discovery → Intune SCEP validate/notify → PKI-connector revocation). He must validate that integration without real Intune/Azure. He's evaluating **IntuneSimulator** as a credible test double (he doesn't have his real product in the environment).
**Surface:** `IntuneSimulator.Host` — startup banner, the faked call chain (AAD instance discovery / openid-config, token endpoint, JWKS/`kid`, Graph service discovery, SCEP validate/notify, revocation), the failure-injection rig (`--print-failure-doc`, `--failure-mode`, the 32-step matrix, `setStep`), the auto-generated TLS cert, and the `ScepIntune*` config table.
**What he attacks:** Would the faked chain fool a real MSAL/Graph connector (does the token's signature verify against the served JWKS; does Graph advertise the right FE services)? Is the failure injection controllable at a specific hop, and does the doc's step numbering match the API? Is the TLS cert correct (basicConstraints CA, serverAuth EKU, SANs) and the trust process documented? Could he wire his product from the docs alone?
**Verdict style:** "Would he adopt it to validate his product's Intune integration?"

## Sam — the security auditor / pentester
**Who:** Independent auditor *engaged with authorization* to assess a client's SCEP service (NDES/Intune-backed CA). He doesn't own the server. He wants `scepclient` as an audit instrument producing defensible evidence — and he's skeptical whether the *tool itself* is safe to run in a client engagement.
**Surface:** the leniency findings (accepts wrong challenge, honors un-advertised renewal, tolerates weak algorithms); coverage of audit-relevant probes (MD5/SHA-1/3DES/small-RSA, challenge enforcement, nonce/replay, spoofed subjects, key-size policy); report quality as evidence (timestamp/target/version/CA-thumbprint *inside* the artifact, accurate RFC citations); and **blast radius** (does the suite issue real certs on the target? is there a `--dry-run`/read-only path? is the footprint disclosed?).
**What he attacks:** Are findings report-grade (RFC ref, what was sent/returned, severity-droppable)? What audit-relevant checks are *missing*? Are reports attributable and machine-parseable? What does running it against a production CA actually create, and does the tool disclose that?
**Verdict style:** "Would he run it on a client engagement? On a *production* CA?"

## Ivan — the SDK integrator & crypto-provider author
**Who:** A .NET developer who wants to consume the **code**, not the CLI — either (a) embed SCEP enrollment in his own app by referencing `ScepWright.Core` / `ScepWright.Crypto`, or (b) implement his own `IScepCrypto` provider (HSM-backed, or a different crypto library) and load it via `--crypto-provider`. He lives in his IDE; his bar is "can I *discover* how to do this, and is the API pleasant and consistent to build on?" *(Code-level persona — he reads `src/` and writes/builds small C# against the assemblies, unlike the black-box personas.)*
**Surface:** the public API of `ScepWright.Core` (`ScepClient`, `ScepRequestBuilder`, `ScepResult<T>`) and `ScepWright.Crypto` (`IScepCrypto`, `CryptoCapabilities`, `IScepKey`, `KeySpec`); the `--crypto-provider <path>` external-assembly loader; the `///` XML doc comments; packaging (`GenerateDocumentationFile`, NuGet); and any getting-started / API-reference docs or samples.
**What he attacks / cares about:**
- **XML docs *shipped*, not just written** — public types/members carry `///` docs (the source does), but is `GenerateDocumentationFile` enabled / is there a NuGet package, so his IDE actually surfaces them on hover/IntelliSense? (Currently: no `GenerateDocumentationFile`, no package — a real discoverability gap.)
- **API consistency** — is the result convention uniform and *principled*? `IScepCrypto` is bool-discriminated (`bool` + `out value` + `out string error`); `Create()`/`Load()` factories return a result enum; async returns `ScepResult<T>` (see `CLAUDE.md`). Is the split documented so it reads as intentional, not accidental? Are naming, nullability, and the sync/async boundary coherent across the public surface?
- **Discoverability** — can a newcomer learn "how do I get a cert programmatically?" and "how do I write a provider?" from docs / XML / a sample, or must he reverse-engineer the CLI source? Is there a getting-started, an API reference, and a sample `IScepCrypto` stub to copy?
- **Embeddability** — can he reference the assemblies and enroll in a handful of lines *without* the CLI? Target frameworks (net8); and does consuming `Core` cleanly keep the crypto library behind the interface, or does BouncyCastle leak into his dependency graph? (`CLAUDE.md`: no crypto-lib references outside `ScepWright.Crypto.*` — verify it actually holds; a couple of files currently appear to reference it directly.)
- **Extensibility** — build a minimal `IScepCrypto` stub, load it with `--crypto-provider <path>`: is the loader contract documented (what type name / constructor it expects), and are errors on a missing / bad / incompatible / wrong-ABI DLL clear and actionable? Does `CryptoCapabilities` let the engine adapt to a provider that supports only a subset (e.g. RSA-only, no PQ)?
- **Stability / versioning** — is the public-vs-internal surface deliberate? Is there a semantic version and any breaking-change signal he can depend on?
**Verdict style:** "Would he build his app on this library / ship a custom provider against it — or vendor his own?"

---

## Meta-role: the independent verifier
A single fresh, **skeptical** agent that re-runs the *backlog* black-box after a fix batch. Given `docs/persona-backlog.md`, it must **not trust the DONE notes** — it reproduces each item against the running binary, runs `dotnet test` to confirm the green/warning claims, prioritizes blockers + high + any net-new logic, judges the by-design items, and returns a per-item `VERIFIED ✅ / NOT-FIXED ❌ / PARTIAL ⚠️ / BY-DESIGN-OK / COULDN'T-CHECK` table plus a prominent list of any item claimed-done-but-not-fixed. Honesty ("couldn't verify X") is required; fabrication is not.

## Meta-role: the focused adversarial agents
2–3 **white-box** agents that attack *only the newly-added code*, not the persona scripts. They may read `src/` to find weak spots but must prove every finding empirically against the running binary. Their mandate: find crashes (HTTP 500, stack traces, unhandled exceptions), wrong results (false pass/fail, silent corruption or downgrade, wrong recipient), and robustness/edge failures (hostile inputs, weird states, encoding). They report confirmed defects with exact repro + severity, *and* the matrix of what held up (so coverage is visible), *and* honest gaps. "I tried hard and couldn't break it" is a valid, valuable result. Split by area of change (e.g. behavioral core / test-and-report engine / issuance-and-CLI). This is the highest-value step once the broad rounds go quiet.
