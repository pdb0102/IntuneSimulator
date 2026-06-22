using System.Collections.Generic;
using System.Text;

namespace ScepWright.Core.Testing;

/// <summary>
/// The documented coverage matrix: for each suite, which check runs, the RFC 8894 section it
/// exercises, and what passing/failing proves. This is the single source of truth — the committed
/// docs/coverage-matrix.md is generated from <see cref="Render"/>, and a test asserts every check the
/// live suites emit appears here, so coverage can never silently drift out of the documentation.
/// </summary>
public static class CoverageMatrixDoc {
    /// <summary>A single coverage-matrix row.</summary>
    public sealed record Entry(string Suite, string Check, string Rfc, string Proves);

    /// <summary>Gets the full set of coverage-matrix entries.</summary>
    public static readonly IReadOnlyList<Entry> Entries = new Entry[] {
        // full - conformance suite: a positive control, then negative checks (rejection = pass) and
        // leniency checks (acceptance of something the RFC permits rejecting = a Finding).
        new("full", "baseline enrollment (positive control)", "RFC 8894 §3.3.1", "a valid PKCSReq is accepted - anchors the negative checks so a reject-everything CA can't score all-green"),
        new("full", "recipientNonce echo",                    "RFC 8894 §3.2.1.1", "the response echoes our senderNonce as recipientNonce (the anti-replay binding); absent/mismatch fails"),
        new("full", "forbidden algorithm (MD5)",              "RFC 8894 §3.2.1.4", "an MD5-signed request is rejected with badAlg"),
        new("full", "corrupted CMS signature",                "RFC 8894 §3.2.1.4", "a tampered signature is rejected with badMessageCheck"),
        new("full", "signingTime skew (+2h)",                 "RFC 8894 §3.2.1.4", "a stale signingTime is rejected with badTime"),
        new("full", "wrong challenge password",               "RFC 8894 §3.3.1",   "a bad challengePassword is rejected (Finding if the CA issues anyway)"),
        new("full", "GetCert unknown serial",                 "RFC 8894 §3.2.1.4", "a GetCert for an unknown serial is rejected with badCertId"),
        new("full", "malformed PKCS#10",                      "RFC 8894 §3.2.1.4", "an unparseable inner CSR is rejected with badRequest"),
        new("full", "RenewalReq when not advertised",         "RFC 8894 §3.5.2",   "honoring a RenewalReq without advertising the Renewal capability is a leniency Finding"),
        new("full", "weak content-encryption (3DES)",         "RFC 8894 §3.5.2",   "accepting a DES-EDE3-CBC-enveloped request is a leniency Finding - a hardened CA should require AES"),
        new("full", "arbitrary subject (no authorization)",   "RFC 8894 §3.3.1",   "issuing for an arbitrary/unauthorized subject is a leniency Finding (production RAs bind the subject to the principal)"),
        new("full", "replayed PKIMessage",                    "RFC 8894 §3.2.1.1", "re-issuing for a byte-identical replayed request is a leniency Finding (no senderNonce/transactionID anti-replay)"),

        // lifecycle - a real end-to-end issuance against the CA.
        new("lifecycle", "GetCACaps",  "RFC 8894 §3.5.1", "the capability advertisement is reachable and parseable"),
        new("lifecycle", "GetCACert",  "RFC 8894 §4.2",   "the CA/RA certificate chain can be retrieved and an envelope recipient selected"),
        new("lifecycle", "enroll",     "RFC 8894 §3.3.1", "a real certificate can be enrolled via PKCSReq"),
        new("lifecycle", "poll",       "RFC 8894 §3.3.3", "a PENDING enrollment can be polled to completion (CertPoll / GetCertInitial); emitted only when enrollment returns PENDING - a CA that issues immediately has nothing to poll"),
        new("lifecycle", "renew",      "RFC 8894 §3.3.1", "an issued certificate can be renewed (RenewalReq)"),
        new("lifecycle", "GetCRL",     "RFC 8894 §4.6",   "a CRL can be retrieved for the issuing CA"),

        // probe - non-destructive capability checks (still enrolls real certs for the digest/POST probes).
        new("probe", "probe SHA-256 digest",      "RFC 8894 §3.5.2",          "the CA accepts a SHA-256-signed request (not only SHA-1)"),
        new("probe", "probe POSTPKIOperation",    "RFC 8894 §3.5.2 / §4.1",   "the CA supports the HTTP POST PKIOperation binding"),
        new("probe", "probe GetNextCACert",       "RFC 8894 §4.7",            "CA-rollover support (GetNextCACert) is present or cleanly absent"),
        new("probe", "probe ML-DSA enrollment",   "RFC 8894 §3.3.1",          "a post-quantum (ML-DSA) subject key can be enrolled (or is cleanly refused)"),
    };

    /// <summary>Renders the coverage matrix as a Markdown document.</summary>
    public static string Render() {
        StringBuilder sb;
        List<string> suites;

        sb = new StringBuilder();
        sb.AppendLine("# SCEP conformance coverage matrix");
        sb.AppendLine();
        sb.AppendLine("What each SCEPwright test suite proves, mapped to the RFC 8894 section it exercises.");
        sb.AppendLine("Generated from `CoverageMatrixDoc` - a test asserts every check the suites emit appears here.");
        sb.AppendLine();
        sb.AppendLine("- **PASSED** - the server behaved as the RFC requires.");
        sb.AppendLine("- **Finding** - the server is *more lenient* than the spec allows (often a security-relevant laxity).");
        sb.AppendLine("- **Skipped** - inconclusive (e.g. PENDING, or a capability the CA doesn't offer).");
        sb.AppendLine();

        suites = new List<string>();
        foreach (Entry e in Entries) {
            if (!suites.Contains(e.Suite)) { suites.Add(e.Suite); }
        }

        foreach (string suite in suites) {
            sb.AppendLine($"## `{suite}`");
            sb.AppendLine();
            sb.AppendLine("| Check | RFC § | What it proves |");
            sb.AppendLine("|---|---|---|");
            foreach (Entry e in Entries) {
                if (e.Suite == suite) {
                    sb.AppendLine($"| {e.Check} | {e.Rfc} | {e.Proves} |");
                }
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
