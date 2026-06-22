using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using ScepWright.Core.Protocol;
using ScepWright.Core.Recipients;
using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>
/// Runs the RFC 8894 compliance matrix against a live server: a positive baseline control, a
/// nonce-echo check, the negative fault-injection checks (rejection = pass), and a replay probe.
/// </summary>
public sealed class ComplianceEngine {
    // What the compliance checks need from a GetCACert bundle: the EnvelopedData *recipient*
    // (encryption-capable cert) that enroll/renew checks must envelope to, the CA *signing* cert's
    // subject used as the GetCert issuer DN, and the (optional) real challenge password so the suite
    // can drive a challenge-protected / NDES CA. For a split-RA / PQ CA the recipient and signing cert
    // differ — enveloping to the signing cert (e.g. an ML-DSA key) fails, so the recipient must come
    // from RecipientSelector.
    private sealed record FullContext(X509Certificate2 Recipient, string IssuerDn, string? Challenge);

    private static readonly ComplianceCheck[] Matrix =
    {
        new("forbidden algorithm (MD5)",      FaultKind.ForbiddenAlgorithm,   FailInfo.BadAlg,          "RFC 8894 §3.2.1.4 (failInfo badAlg); §2.9 (mandatory algorithms)"),
        new("corrupted CMS signature",        FaultKind.CorruptedSignature,   FailInfo.BadMessageCheck, "RFC 8894 §3.2.1.4 (failInfo badMessageCheck)"),
        new("signingTime skew (+2h)",         FaultKind.SkewedSigningTime,    FailInfo.BadTime,         "RFC 8894 §3.2.1.4 (failInfo badTime)"),
        new("wrong challenge password",       FaultKind.WrongChallenge,       FailInfo.None,            "RFC 8894 §3.3.1 (PKCSReq challengePassword)"),
        new("GetCert unknown serial",         FaultKind.UnknownCertId,        FailInfo.BadCertId,       "RFC 8894 §3.2.1.4 (failInfo badCertId)"),
        new("malformed PKCS#10",              FaultKind.MalformedRequest,     FailInfo.BadRequest,      "RFC 8894 §3.2.1.4 (failInfo badRequest)"),
        new("RenewalReq when not advertised", FaultKind.RenewalNotAdvertised, FailInfo.None,            "RFC 8894 §3.5.2 (Renewal capability)"),
        new("weak content-encryption (3DES)", FaultKind.WeakContentEncryption, FailInfo.None,           "RFC 8894 §3.5.2 (GetCACaps AES vs DES3 content-encryption)",
            "server accepted a request enveloped with weak content-encryption (DES-EDE3-CBC) — a hardened CA should require AES"),
        new("arbitrary subject (no authorization)", FaultKind.SpoofedSubject, FailInfo.None,            "RFC 8894 §3.3.1 (PKCSReq subject; subject binding is RA policy)",
            "server issued for an arbitrary/unauthorized subject — no subject-name authorization (acceptable for an open test CA; a production RA should bind the subject to the authenticated principal)"),
    };

    /// <summary>Runs the full compliance matrix and returns the report. Issues real certificates for the positive checks.</summary>
    public TestReport RunFull(ScepClient client, IReadOnlyList<X509Certificate2> ca_bundle, ScepCapabilities caps, string? challenge = null) {
        TestReport report;
        Stopwatch total;
        FullContext ctx;
        System.Action<X509Certificate2> capture;

        report = new TestReport { ServerId = client.Server.Id, Mode = "full" };
        ctx = ResolveContext(ca_bundle, challenge);
        total = Stopwatch.StartNew();
        // Record the real certificates this run mints so the report can list them for cleanup/revocation.
        capture = c => report.Footprint.Add(IssuedCert.From(c));
        client.CertificateIssued += capture;
        try {
            // Positive control FIRST: a valid request must be accepted. Every other check is a NEGATIVE check
            // (rejection = pass), so without this a challenge-protected CA that rejects everything would score
            // all-green and prove nothing. A failed baseline names the likely missing challenge and, being
            // FAILED, drives a non-zero exit so CI can't pass on a misconfigured run.
            report.Results.Add(RunBaselineEnroll(client, ctx));
            report.Results.Add(RunNonceEcho(client, ctx));
            foreach (ComplianceCheck check in Matrix) {
                report.Results.Add(RunCheck(client, ctx, caps, check));
            }
            report.Results.Add(RunReplay(client, ctx));
        } finally {
            client.CertificateIssued -= capture;
        }
        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    // Picks the envelope recipient (encryption-capable cert) and the issuer DN (signing-cert subject)
    // from the GetCACert bundle. Falls back to the first cert when the server presents only one (the
    // dual-use case) or no encryption-capable recipient, preserving the single-cert behavior.
    private static FullContext ResolveContext(IReadOnlyList<X509Certificate2> ca_bundle, string? challenge) {
        RecipientSelection selection;
        X509Certificate2 recipient;
        X509Certificate2 issuer;

        selection = RecipientSelector.Select(ca_bundle);
        recipient = selection.EncryptionCertificate ?? selection.SigningCertificate ?? ca_bundle[0];
        issuer = selection.SigningCertificate ?? ca_bundle[0];
        return new FullContext(recipient, issuer.Subject, challenge);
    }

    // Positive control: submit a valid PKCSReq (with the supplied challenge) and require success.
    //  - Success  -> Passed.
    //  - Pending  -> Skipped (CA holding for manual approval; the suite is inconclusive but not broken).
    //  - Rejected -> Failed. When no challenge was supplied and the CA answered badRequest, say so —
    //                that is the classic "forgot --challenge" footgun that otherwise reads as all-green.
    private static CheckResult RunBaselineEnroll(ScepClient client, FullContext ctx) {
        Stopwatch sw;
        ScepResult<EnrollOutcome> result;
        PkiStatus status;
        FailInfo got;
        string why;

        sw = Stopwatch.StartNew();
        result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, null, MessageType.PkcsReq);
        sw.Stop();

        status = result.Value?.PkiStatus ?? PkiStatus.Failure;
        got = result.Value?.FailInfo ?? FailInfo.None;

        if (status == PkiStatus.Pending) {
            return new CheckResult("baseline enrollment (positive control)", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                status, "server returned PENDING — cannot assess (CA holding for manual approval)", "RFC 8894 §3.3.1 (PKCSReq)", sw.Elapsed);
        }
        if (status == PkiStatus.Success) {
            return new CheckResult("baseline enrollment (positive control)", CheckOutcome.Passed, FailInfo.None, FailInfo.None,
                status, "a valid request was accepted", "RFC 8894 §3.3.1 (PKCSReq)", sw.Elapsed);
        }

        why = ctx.Challenge is null && got == FailInfo.BadRequest
            ? "a valid request was REJECTED (failInfo BadRequest) and no challenge was supplied — the CA likely requires one (pass --challenge / --ndes / --simulator); the negative checks below are inconclusive"
            : $"a valid request was REJECTED (failInfo {got}) — the CA could not issue a baseline certificate" + (ctx.Challenge != null ? " even with the supplied challenge" : string.Empty);
        return new CheckResult("baseline enrollment (positive control)", CheckOutcome.Failed, FailInfo.None, got,
            status, why, "RFC 8894 §3.3.1 (PKCSReq)", sw.Elapsed);
    }

    // RFC 8894 §3.2.1.1: a SCEP response MUST carry a recipientNonce equal to the senderNonce of the
    // request it answers (it ties the reply to our challenge and defeats a replayed CertRep). The server
    // must echo it regardless of pkiStatus, so this is assessed on whatever response comes back; only a
    // missing response (transport/crypto failure) is inconclusive.
    private static CheckResult RunNonceEcho(ScepClient client, FullContext ctx) {
        Stopwatch sw;
        ScepResult<EnrollOutcome> result;
        byte[]? sent;
        byte[]? echoed;
        PkiStatus status;

        const string Rfc = "RFC 8894 §3.2.1.1 (recipientNonce echoes senderNonce)";

        sw = Stopwatch.StartNew();
        result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, null, MessageType.PkcsReq);
        sw.Stop();

        if (result.Value is null) {
            return new CheckResult("recipientNonce echo", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "no response could be obtained to assess the nonce echo", Rfc, sw.Elapsed);
        }

        sent = result.Value.SenderNonce;
        echoed = result.Value.RecipientNonce;
        status = result.Value.PkiStatus;

        if (echoed is null) {
            return new CheckResult("recipientNonce echo", CheckOutcome.Failed, FailInfo.None, FailInfo.None,
                status, "server returned no recipientNonce (RFC 8894 §3.2.1.1 requires it)", Rfc, sw.Elapsed);
        }
        if (sent is null || !NonceEquals(sent, echoed)) {
            return new CheckResult("recipientNonce echo", CheckOutcome.Failed, FailInfo.None, FailInfo.None,
                status, "recipientNonce did not match the senderNonce we sent", Rfc, sw.Elapsed);
        }
        return new CheckResult("recipientNonce echo", CheckOutcome.Passed, FailInfo.None, FailInfo.None,
            status, "recipientNonce echoed our senderNonce", Rfc, sw.Elapsed);
    }

    private static bool NonceEquals(byte[] a, byte[] b) {
        int i;

        if (a.Length != b.Length) { return false; }
        for (i = 0; i < a.Length; i++) {
            if (a[i] != b[i]) { return false; }
        }
        return true;
    }

    // RFC 8894 §3.2.1.1: the per-message senderNonce is the anti-replay mechanism. Build one valid
    // request, send the byte-identical bytes twice, and judge the second response: re-issuing for an
    // exact replay is more lenient than the nonce mechanism intends (a Finding); rejecting it passes.
    // Inconclusive when the request can't be built/sent or the baseline send isn't even accepted.
    private static CheckResult RunReplay(ScepClient client, FullContext ctx) {
        Stopwatch sw;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string build_error;
        ReplayProbe probe;

        const string Rfc = "RFC 8894 §3.2.1.1 (senderNonce/recipientNonce anti-replay)";

        sw = Stopwatch.StartNew();
        builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(ctx.Recipient)
            .MessageType(MessageType.PkcsReq)
            .Subject("CN=replay-" + System.Guid.NewGuid().ToString("N").Substring(0, 8))
            // Deliberate baseline probe: rsa:2048 isolates the compliance behavior under test from key choice.
            .KeySpec("rsa:2048");
        if (ctx.Challenge != null) { builder.Challenge(ctx.Challenge); }

        if (!builder.Build(out message, out subject_key, out build_error)) {
            sw.Stop();
            return new CheckResult("replayed PKIMessage", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "could not build a request to replay: " + build_error, Rfc, sw.Elapsed);
        }

        probe = client.ProbeReplay(message, subject_key);
        sw.Stop();

        if (!probe.Sent) {
            return new CheckResult("replayed PKIMessage", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "request could not be transmitted twice: " + probe.Error, Rfc, sw.Elapsed);
        }
        if (probe.First != PkiStatus.Success) {
            return new CheckResult("replayed PKIMessage", CheckOutcome.Skipped, FailInfo.None, probe.FirstFail,
                probe.First, $"baseline send was not accepted (failInfo {probe.FirstFail}) — replay inconclusive", Rfc, sw.Elapsed);
        }
        if (probe.Second == PkiStatus.Success) {
            return new CheckResult("replayed PKIMessage", CheckOutcome.Finding, FailInfo.None, FailInfo.None,
                probe.Second, "server re-issued for a byte-identical replayed request (no senderNonce/transactionID anti-replay)", Rfc, sw.Elapsed);
        }
        return new CheckResult("replayed PKIMessage", CheckOutcome.Passed, FailInfo.None, probe.SecondFail,
            probe.Second, $"server rejected the replayed request (failInfo {probe.SecondFail})", Rfc, sw.Elapsed);
    }

    private CheckResult RunCheck(ScepClient client, FullContext ctx, ScepCapabilities caps, ComplianceCheck check) {
        Stopwatch sw;
        PkiStatus status;
        FailInfo got;
        bool responded;

        sw = Stopwatch.StartNew();
        Execute(client, ctx, caps, check, out status, out got, out responded);
        sw.Stop();
        return Classify(check, status, got, responded, sw.Elapsed);
    }

    // Runs the fault and reports the server's pkiStatus/failInfo plus <paramref name="responded"/>:
    // whether a real SCEP response was actually decoded. A transport error / HTTP 500 / a request that
    // can't even be enveloped (no encryption-capable recipient) yields NO response — that must not be
    // mistaken for a server rejection, or Classify would false-PASS the negative (Expected==None) checks.
    private void Execute(ScepClient client, FullContext ctx, ScepCapabilities caps, ComplianceCheck check,
                         out PkiStatus status, out FailInfo got, out bool responded) {
        ScepResult<EnrollOutcome> result;
        ScepResult<X509Certificate2> cert_result;

        status = PkiStatus.Failure;
        got = FailInfo.None;
        responded = false;

        if (check.Kind == FaultKind.UnknownCertId) {
            // GetCert envelopes to the recipient internally; only the issuer DN (the CA signing cert) matters here.
            // ProjectCert returns ServerFailure only when a real CertRep came back (vs a transport failure).
            cert_result = client.GetCert(ctx.IssuerDn, "00DEADBEEF");
            responded = cert_result.IsOk || cert_result.Status == ScepClientResult.ServerFailure;
            status = cert_result.IsOk ? PkiStatus.Success : PkiStatus.Failure;
            got = cert_result.IsOk ? FailInfo.None : ExtractFailInfo(cert_result.Error);
            return;
        }

        if (check.Kind == FaultKind.RenewalNotAdvertised) {
            // A RenewalReq needs an existing cert+key, so enroll first then renew with it.
            ExecuteRenewal(client, ctx.Recipient, ctx.Challenge, out status, out got, out responded);
            return;
        }

        // Every check but WrongChallenge presents the real challenge so a challenge-protected CA rejects
        // for the fault under test, not for a missing challenge; WrongChallenge deliberately sends a bad one.
        switch (check.Kind) {
            case FaultKind.ForbiddenAlgorithm:
                result = SubmitEnroll(client, ctx.Recipient, "MD5", ctx.Challenge, null, MessageType.PkcsReq);
                break;
            case FaultKind.CorruptedSignature:
                result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, new FaultDirectives { CorruptSignature = true }, MessageType.PkcsReq);
                break;
            case FaultKind.SkewedSigningTime:
                result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, new FaultDirectives { SigningTimeSkew = System.TimeSpan.FromHours(2) }, MessageType.PkcsReq);
                break;
            case FaultKind.WrongChallenge:
                result = SubmitEnroll(client, ctx.Recipient, null, "definitely-wrong-" + System.Guid.NewGuid().ToString("N"), null, MessageType.PkcsReq);
                break;
            case FaultKind.MalformedRequest:
                result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, new FaultDirectives { CorruptInnerContent = true }, MessageType.PkcsReq);
                break;
            case FaultKind.WeakContentEncryption:
                result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, null, MessageType.PkcsReq, cipher: "DES-EDE3-CBC");
                break;
            case FaultKind.SpoofedSubject:
                result = SubmitEnroll(client, ctx.Recipient, null, ctx.Challenge, null, MessageType.PkcsReq, subject: "CN=admin,O=Spoofed Corp,OU=unauthorized");
                break;
            default:
                return;
        }

        responded = result.Value != null;
        status = result.Value?.PkiStatus ?? PkiStatus.Failure;
        got = result.Value?.FailInfo ?? FailInfo.None;
    }

    // The builder requires a SignerCertificate+SignerKey for a RenewalReq, so a real renewal must
    // start from an issued cert: enroll once, then submit a proper RenewalReq signed by it. A server
    // that honors the renewal despite never advertising the Renewal cap is the "more lenient" finding.
    private static void ExecuteRenewal(ScepClient client, X509Certificate2 recipient, string? challenge, out PkiStatus status, out FailInfo got, out bool responded) {
        string subject;
        ScepRequestBuilder enroll_builder;
        PkiMessage enroll_message;
        IScepKey enroll_key;
        string enroll_error;
        ScepResult<EnrollOutcome> enroll_result;
        ScepRequestBuilder renew_builder;
        PkiMessage renew_message;
        IScepKey renew_key;
        string renew_error;
        ScepResult<EnrollOutcome> renew_result;

        status = PkiStatus.Failure;
        got = FailInfo.None;
        responded = false;

        subject = "CN=renew-seed-" + System.Guid.NewGuid().ToString("N").Substring(0, 8);

        enroll_builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(recipient)
            .MessageType(MessageType.PkcsReq)
            .Subject(subject)
            // Deliberate baseline probe: rsa:2048 isolates the compliance behavior under test from key choice.
            .KeySpec("rsa:2048");
        if (challenge != null) { enroll_builder.Challenge(challenge); }
        if (!enroll_builder.Build(out enroll_message, out enroll_key, out enroll_error)) {
            return;
        }
        enroll_result = client.SubmitPkiOperation(enroll_message, enroll_key, null);
        if (!enroll_result.IsOk || enroll_result.Value?.Certificate is null) {
            return;
        }

        renew_builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(recipient)
            .MessageType(MessageType.RenewalReq)
            .Subject(subject)
            // Deliberate baseline probe: rsa:2048 isolates the compliance behavior under test from key choice.
            .KeySpec("rsa:2048")
            .SignerCertificate(enroll_result.Value.Certificate)
            .SignerKey(enroll_key);
        if (challenge != null) { renew_builder.Challenge(challenge); }
        if (!renew_builder.Build(out renew_message, out renew_key, out renew_error)) {
            return;
        }
        renew_result = client.SubmitPkiOperation(renew_message, renew_key, null);
        responded = renew_result.Value != null;
        status = renew_result.Value?.PkiStatus ?? PkiStatus.Failure;
        got = renew_result.Value?.FailInfo ?? FailInfo.None;
    }

    private static ScepResult<EnrollOutcome> SubmitEnroll(ScepClient client, X509Certificate2 recipient, string? digest,
                                                          string? challenge, FaultDirectives? faults, MessageType message_type,
                                                          string? cipher = null, string? subject = null) {
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;

        builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(recipient)
            .MessageType(message_type)
            .Subject(subject ?? ("CN=compliance-" + System.Guid.NewGuid().ToString("N").Substring(0, 8)))
            // Deliberate baseline probe: rsa:2048 isolates the compliance behavior under test from key choice.
            .KeySpec("rsa:2048");
        if (digest != null) { builder.Digest(digest); }
        if (cipher != null) { builder.Cipher(cipher); }
        if (challenge != null) { builder.Challenge(challenge); }
        if (faults != null) { builder.AllowFaults(faults); }

        if (!builder.Build(out message, out subject_key, out error)) {
            return ScepResult<EnrollOutcome>.Fail(ScepClientResult.InvalidArgument, error);
        }
        return client.SubmitPkiOperation(message, subject_key, builder.Faults);
    }

    private static CheckResult Classify(ComplianceCheck check, PkiStatus status, FailInfo got, bool responded, System.TimeSpan elapsed) {
        CheckOutcome outcome;
        string why;

        if (!responded) {
            // No SCEP response was decoded at all (transport error / HTTP 500 / the request could not be
            // enveloped because the CA exposes no encryption-capable recipient). This is inconclusive — it
            // must NOT read as "the server rejected as expected", which would false-PASS the Expected==None
            // negative checks and write audit evidence that lies about a CA that can't even issue.
            return new CheckResult(check.Name, CheckOutcome.Skipped, check.Expected, FailInfo.None, status,
                "no SCEP response could be obtained (transport error / HTTP 500 / no envelope recipient) — check inconclusive", check.RfcReference, elapsed);
        }

        if (status == PkiStatus.Pending) {
            // The CA is holding the request for manual approval, so this check can't be assessed — that's
            // not a compliance failure (a PENDING-mode server makes every check inconclusive).
            return new CheckResult(check.Name, CheckOutcome.Skipped, check.Expected, FailInfo.None, status,
                "server returned PENDING — cannot assess (CA holding for manual approval)", check.RfcReference, elapsed);
        }

        if (check.Expected == FailInfo.None) {
            // Expect a generic FAILURE (server-specific failInfo). Acceptance = the server rejected at all.
            if (status == PkiStatus.Failure) {
                outcome = CheckOutcome.Passed;
                why = $"server rejected as expected (failInfo {got})";
            } else {
                outcome = CheckOutcome.Finding;
                why = check.FindingWhy ?? "server accepted a request the RFC lets it reject (more lenient than spec)";
            }
        } else if (status == PkiStatus.Failure && got == check.Expected) {
            outcome = CheckOutcome.Passed;
            why = $"got expected {check.Expected}";
        } else if (status == PkiStatus.Success) {
            outcome = CheckOutcome.Finding;
            why = $"expected {check.Expected}, but server SUCCEEDED (more lenient than RFC 8894)";
        } else {
            outcome = CheckOutcome.Failed;
            why = $"expected {check.Expected}, got {got} (status {status})";
        }
        return new CheckResult(check.Name, outcome, check.Expected, got, status, why, check.RfcReference, elapsed);
    }

    private static FailInfo ExtractFailInfo(string error) {
        // ScepClient.ProjectCert embeds the FailInfo enum name in its error message (e.g. "... failInfo BadCertId").
        if (error.Contains("BadCertId")) { return FailInfo.BadCertId; }
        if (error.Contains("BadMessageCheck")) { return FailInfo.BadMessageCheck; }
        if (error.Contains("BadRequest")) { return FailInfo.BadRequest; }
        if (error.Contains("BadTime")) { return FailInfo.BadTime; }
        if (error.Contains("BadAlg")) { return FailInfo.BadAlg; }
        return FailInfo.None;
    }
}
