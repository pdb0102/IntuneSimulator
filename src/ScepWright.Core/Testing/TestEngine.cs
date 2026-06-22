using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using ScepWright.Core.Protocol;
using ScepWright.Core.Storage;
using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>
/// Runs the SCEPwright test suites: the full compliance matrix, the happy-path lifecycle smoke test,
/// the capability probe (which deliberately steps beyond advertised caps), and the read-only dry run.
/// </summary>
public sealed class TestEngine {
    /// <summary>Runs the full conformance/compliance matrix (delegates to <see cref="ComplianceEngine"/>).</summary>
    public TestReport RunFull(ScepClient client, System.Collections.Generic.IReadOnlyList<X509Certificate2> ca_bundle, ScepCapabilities caps, string? challenge = null) {
        return new ComplianceEngine().RunFull(client, ca_bundle, caps, challenge);
    }

    /// <summary>
    /// Runs the happy-path round-trip a real client makes (caps → cacert → enroll → poll-if-pending →
    /// renew → CRL). A step is skipped only when its prerequisite failed. Issues real certificates.
    /// </summary>
    public TestReport RunLifecycle(ScepClient client, CertStore store, UseRecordLog log, string? challenge = null) {
        TestReport report;
        Stopwatch total;
        bool caps_ok;
        bool ca_ok;
        X509Certificate2? ca_cert;
        bool enroll_ok;
        string? cert_id;
        bool pending;
        System.Action<X509Certificate2> capture;

        report = new TestReport { ServerId = client.Server.Id, Mode = "lifecycle" };
        total = Stopwatch.StartNew();

        caps_ok = Step(report, "GetCACaps", () => client.GetCaCaps().IsOk);

        ca_cert = null;
        ca_ok = StepCaCert(report, client, out ca_cert);

        if (!ca_ok || ca_cert == null) {
            Skip(report, "enroll", "GetCACert failed");
            Skip(report, "renew", "enroll skipped");
            Skip(report, "GetCRL", "GetCACert failed");
            total.Stop();
            report.TotalElapsed = total.Elapsed;
            return report;
        }

        cert_id = null;
        pending = false;
        // Record the real certificates enroll + renew mint, for cleanup/revocation.
        capture = c => report.Footprint.Add(IssuedCert.From(c));
        client.CertificateIssued += capture;
        enroll_ok = StepEnroll(report, client, ca_cert, store, log, challenge, out cert_id, out pending);

        // poll-if-pending: only attempt a poll when the enroll actually came back PENDING.
        if (pending) {
            Step(report, "poll", () => client.Poll(ca_cert!.Subject, "CN=lifecycle", System.Guid.NewGuid().ToString("N")).Status != ScepClientResult.NetworkError);
        }

        if (!enroll_ok || cert_id == null) {
            Skip(report, "renew", "enroll failed");
        } else {
            Step(report, "renew", () => client.RenewCertificate(cert_id!, store, log, challenge: challenge).IsOk);
        }

        Step(report, "GetCRL", () => client.GetCrl(ca_cert!.Subject, "01").IsOk);

        client.CertificateIssued -= capture;
        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    /// <summary>
    /// Probes capabilities by deliberately stepping beyond what's advertised (SHA-256, POST,
    /// GetNextCACert, ML-DSA). Reports PASSED (worked and advertised), FINDING (worked but never
    /// advertised), or FAILED. Issues real certificates for the enroll-based probes.
    /// </summary>
    public TestReport RunProbe(ScepClient client, string? challenge = null) {
        TestReport report;
        Stopwatch total;
        ScepCapabilities caps;
        ScepResult<ScepCapabilities> caps_result;
        System.Action<X509Certificate2> capture;

        report = new TestReport { ServerId = client.Server.Id, Mode = "probe" };
        total = Stopwatch.StartNew();

        caps_result = client.GetCaCaps();
        caps = caps_result.IsOk ? caps_result.Value : ScepCapabilities.Parse(string.Empty);

        // Record the real certificates the enroll probes mint, for cleanup/revocation.
        capture = c => report.Footprint.Add(IssuedCert.From(c));
        client.CertificateIssued += capture;
        ProbeDigest(report, client, caps, challenge);
        ProbePost(report, client, caps, challenge);
        ProbeGetNextCa(report, client, caps);
        ProbePq(report, client, challenge);
        client.CertificateIssued -= capture;

        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    /// <summary>
    /// Runs the read-only suite: the disclosure-worthy checks a real client cares about, minus anything
    /// that enrolls or renews. Safe to point at a CA you don't own — issues no certificates.
    /// <see cref="TestReport.Failed"/> is set only when a read-only check genuinely fails (e.g. the
    /// server presents no envelope-capable recipient).
    /// </summary>
    public TestReport RunDryRun(ScepClient client) {
        TestReport report;
        Stopwatch total;
        Stopwatch sw;
        ScepResult<ScepCapabilities> caps_result;
        ScepCapabilities caps;

        report = new TestReport { ServerId = client.Server.Id, Mode = "dry-run" };
        total = Stopwatch.StartNew();

        sw = Stopwatch.StartNew();
        caps_result = client.GetCaCaps();
        sw.Stop();
        caps = caps_result.IsOk ? caps_result.Value : ScepCapabilities.Parse(string.Empty);
        Record(report, "GetCACaps", caps_result.IsOk, caps_result.IsOk ? "ok" : "GetCACaps failed: " + caps_result.Error, sw.Elapsed);

        DryRunCaCertAndRecipient(report, client);
        DryRunCaps(report, caps);
        ProbeGetNextCa(report, client, caps);

        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    // GetCACert + the recipient verdict in one pass (one GetCACert call): can a SCEP PKIOperation even
    // be enveloped to this server? A missing encryption-capable recipient is a hard FAILED (like
    // `diagnose`'s BROKEN verdict), because nothing can enroll against such a CA.
    private static void DryRunCaCertAndRecipient(TestReport report, ScepClient client) {
        Stopwatch sw;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> ca_result;
        ScepWright.Core.Recipients.RecipientSelection selection;
        bool ca_ok;
        bool can_envelope;
        string why;

        sw = Stopwatch.StartNew();
        ca_result = client.GetCaCert();
        ca_ok = ca_result.IsOk && ca_result.Value.Count > 0;
        sw.Stop();
        Record(report, "GetCACert", ca_ok, ca_ok ? "ok" : "GetCACert failed", sw.Elapsed);

        if (!ca_ok) {
            report.Results.Add(new CheckResult("recipient selection", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "GetCACert failed; cannot assess the envelope recipient", "RFC 8894 §3.1", System.TimeSpan.Zero));
            return;
        }

        sw = Stopwatch.StartNew();
        selection = ScepWright.Core.Recipients.RecipientSelector.Select(ca_result.Value);
        can_envelope = selection.CanEnvelope && selection.EncryptionCertificate is not null;
        sw.Stop();
        why = can_envelope
            ? "envelope-capable recipient present: " + selection.EncryptionCertificate!.Subject
            : "no encryption-capable recipient — SCEP PKIOperation cannot be enveloped";
        report.Results.Add(new CheckResult("recipient selection", can_envelope ? CheckOutcome.Passed : CheckOutcome.Failed,
            FailInfo.None, FailInfo.None, can_envelope ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894 §3.1", sw.Elapsed));
    }

    // Enrollment-capability sanity (read-only): a CA that advertises no SHA-2 digest or no
    // POSTPKIOperation will turn away modern clients (e.g. Jamf). Surfaced as a FINDING, not a failure.
    private static void DryRunCaps(TestReport report, ScepCapabilities caps) {
        System.Collections.Generic.List<string> missing;
        bool ok;
        string why;

        missing = new System.Collections.Generic.List<string>();
        if (!caps.PostPkiOperation) { missing.Add("POSTPKIOperation"); }
        if (!caps.Sha256 && !caps.Sha512) { missing.Add("a SHA-2 digest (SHA-256/SHA-512)"); }

        ok = missing.Count == 0;
        why = ok ? "advertises SHA-2 + POSTPKIOperation" : "CACaps lacks " + string.Join(" and ", missing) + " — some modern clients will refuse to enroll";
        report.Results.Add(new CheckResult("enrollment capabilities", ok ? CheckOutcome.Passed : CheckOutcome.Finding,
            FailInfo.None, FailInfo.None, ok ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894 §3.5.2", System.TimeSpan.Zero));
    }

    // -------------------------------------------------------------------------
    // Lifecycle helpers
    // -------------------------------------------------------------------------

    private static bool StepCaCert(TestReport report, ScepClient client, out X509Certificate2? ca_cert) {
        Stopwatch sw;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> result;
        bool ok;

        ca_cert = null;
        sw = Stopwatch.StartNew();
        try {
            result = client.GetCaCert();
            ok = result.IsOk && result.Value.Count > 0;
            if (ok) { ca_cert = result.Value[0]; }
        } catch (System.Exception) {
            ok = false;
        }
        sw.Stop();
        Record(report, "GetCACert", ok, ok ? "ok" : "step failed", sw.Elapsed);
        return ok;
    }

    private static bool StepEnroll(TestReport report, ScepClient client, X509Certificate2 ca_cert, CertStore store, UseRecordLog log,
                                   string? challenge, out string? cert_id, out bool pending) {
        Stopwatch sw;
        KeySpec spec;
        IScepKey key;
        string key_error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> result;
        bool ok;
        string why;

        cert_id = null;
        pending = false;

        sw = Stopwatch.StartNew();
        // Deliberate baseline probe: rsa:2048 is the lowest-common-denominator key for this smoke test.
        if (!KeySpec.Parse("rsa:2048", out spec, out key_error)) {
            sw.Stop();
            Record(report, "enroll", false, "key spec parse failed: " + key_error, sw.Elapsed);
            return false;
        }
        if (!client.Crypto.GenerateKey(spec, out key, out key_error)) {
            sw.Stop();
            Record(report, "enroll", false, "key generation failed: " + key_error, sw.Elapsed);
            return false;
        }

        request = new EnrollRequest {
            Subject = "CN=lifecycle-" + System.Guid.NewGuid().ToString("N").Substring(0, 8),
            Key = key,
            // Pass the challenge so the suite can drive a challenge-protected / NDES CA.
            ChallengePassword = challenge,
            // Leave CaCertificate null so GetNewCertificate selects the encryption recipient itself —
            // the signing cert (ca_cert here) is the wrong envelope target for split-RA / PQ CAs.
        };

        try {
            result = client.GetNewCertificate(request, store, log);
        } catch (System.Exception ex) {
            sw.Stop();
            Record(report, "enroll", false, "enroll threw: " + ex.Message, sw.Elapsed);
            return false;
        }
        sw.Stop();

        pending = result.Status == ScepClientResult.Pending;
        ok = result.IsOk && result.Value?.Certificate != null;
        if (ok) { cert_id = result.Value!.Certificate!.Thumbprint.ToLowerInvariant(); }

        if (pending) {
            // PENDING is the CA holding the request for manual approval — the normal poll path, not a failure.
            report.Results.Add(new CheckResult("enroll", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Pending, "enroll returned PENDING (CA holding for manual approval; poll to complete)", "RFC 8894", sw.Elapsed));
            return false;
        }

        why = ok ? "issued" : "enroll failed: " + result.Error;
        Record(report, "enroll", ok, why, sw.Elapsed);
        return ok;
    }

    // -------------------------------------------------------------------------
    // Probe helpers
    // -------------------------------------------------------------------------

    private static void ProbeDigest(TestReport report, ScepClient client, ScepCapabilities caps, string? challenge) {
        Stopwatch sw;
        ProbeEnroll enroll;
        bool advertised;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        sw = Stopwatch.StartNew();
        advertised = caps.Sha256;
        enroll = ProbeEnroll.Failed;
        try {
            ca_result = ResolveCaCert(client);
            if (ca_result.IsOk) {
                // Deliberate baseline probe: rsa:2048 is the lowest-common-denominator key for this check.
                enroll = SubmitEnrollWithKeySpec(client, ca_result.Value, "rsa:2048", "SHA-256", challenge);
            }
        } catch (System.Exception) {
            enroll = ProbeEnroll.Failed;
        }
        sw.Stop();

        if (enroll == ProbeEnroll.Pending) {
            outcome = CheckOutcome.Skipped;
            why = "server returned PENDING — cannot assess (CA holding for manual approval)";
        } else if (enroll == ProbeEnroll.Failed) {
            outcome = CheckOutcome.Failed;
            why = "SHA-256 enrollment did not succeed";
        } else if (advertised) {
            outcome = CheckOutcome.Passed;
            why = "SHA-256 worked and is advertised";
        } else {
            outcome = CheckOutcome.Finding;
            why = "SHA-256 worked but the server never advertised it";
        }
        report.Results.Add(new CheckResult("probe SHA-256 digest", outcome, FailInfo.None, FailInfo.None,
            ProbeStatus(enroll), why, "RFC 8894 §3.5.2", sw.Elapsed));
    }

    private static PkiStatus ProbeStatus(ProbeEnroll enroll) {
        if (enroll == ProbeEnroll.Succeeded) { return PkiStatus.Success; }
        if (enroll == ProbeEnroll.Pending) { return PkiStatus.Pending; }
        return PkiStatus.Failure;
    }

    private static void ProbePost(TestReport report, ScepClient client, ScepCapabilities caps, string? challenge) {
        Stopwatch sw;
        ProbeEnroll enroll;
        bool advertised;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        sw = Stopwatch.StartNew();
        advertised = caps.PostPkiOperation;
        enroll = ProbeEnroll.Failed;
        // The client posts when Server.PreferPost is set; if it is not, we cannot exercise POST here.
        try {
            if (client.Server.PreferPost) {
                ca_result = ResolveCaCert(client);
                if (ca_result.IsOk) {
                    // Deliberate baseline probe: rsa:2048 is the lowest-common-denominator key for this check.
                    enroll = SubmitEnrollWithKeySpec(client, ca_result.Value, "rsa:2048", "SHA-256", challenge);
                }
            }
        } catch (System.Exception) {
            enroll = ProbeEnroll.Failed;
        }
        sw.Stop();

        if (!client.Server.PreferPost) {
            outcome = CheckOutcome.Skipped;
            why = "client not configured to POST (Server.PreferPost is false)";
        } else if (enroll == ProbeEnroll.Pending) {
            outcome = CheckOutcome.Skipped;
            why = "server returned PENDING — cannot assess (CA holding for manual approval)";
        } else if (enroll == ProbeEnroll.Failed) {
            outcome = CheckOutcome.Failed;
            why = "POSTPKIOperation enrollment did not succeed";
        } else if (advertised) {
            outcome = CheckOutcome.Passed;
            why = "POST worked and is advertised";
        } else {
            outcome = CheckOutcome.Finding;
            why = "POST worked but the server never advertised POSTPKIOperation";
        }
        report.Results.Add(new CheckResult("probe POSTPKIOperation", outcome, FailInfo.None, FailInfo.None,
            ProbeStatus(enroll), why, "RFC 8894 §3.5.2 (POSTPKIOperation capability); §4.1 (HTTP POST)", sw.Elapsed));
    }

    private static void ProbeGetNextCa(TestReport report, ScepClient client, ScepCapabilities caps) {
        Stopwatch sw;
        bool worked;
        bool advertised;
        CheckOutcome outcome;
        string why;
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> result;

        sw = Stopwatch.StartNew();
        advertised = caps.GetNextCaCert;
        worked = false;
        try {
            result = client.GetNextCaCert();
            worked = result.IsOk && result.Value.Count > 0;
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (!worked) {
            // Absent GetNextCACert is only a failure if the CA *advertised* it; otherwise it is an
            // optional operation the CA legitimately doesn't offer (skip, don't fail).
            outcome = advertised ? CheckOutcome.Failed : CheckOutcome.Skipped;
            why = advertised ? "GetNextCACert advertised but did not return a certificate" : "GetNextCACert not advertised or supported (optional)";
        } else if (advertised) {
            outcome = CheckOutcome.Passed;
            why = "GetNextCACert worked and is advertised";
        } else {
            outcome = CheckOutcome.Finding;
            why = "GetNextCACert worked but the server never advertised it";
        }
        report.Results.Add(new CheckResult("probe GetNextCACert", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894 §4.7", sw.Elapsed));
    }

    // GetCACaps has no PQ keyword, so any ML-DSA success is a FINDING (PQ-capable / under-advertised
    // CA); a failure against a classical-only CA is the expected FAILED. Wrapped so it never throws.
    private static void ProbePq(TestReport report, ScepClient client, string? challenge) {
        Stopwatch sw;
        bool worked;
        CheckOutcome outcome;
        string why;
        ScepResult<X509Certificate2> ca_result;

        if (!client.Crypto.Capabilities.PqTiers.TierA) {
            report.Results.Add(new CheckResult("probe ML-DSA enrollment", CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
                PkiStatus.Failure, "loaded provider does not implement PQ tier A", "spec §14 (empirical PQ probe)", System.TimeSpan.Zero));
            return;
        }

        sw = Stopwatch.StartNew();
        worked = false;
        try {
            ca_result = ResolveCaCert(client);
            if (ca_result.IsOk) {
                worked = SubmitEnrollWithKeySpec(client, ca_result.Value, "ml-dsa:65", "SHA-256", challenge) == ProbeEnroll.Succeeded;
            }
        } catch (System.Exception) {
            worked = false;
        }
        sw.Stop();

        if (worked) {
            outcome = CheckOutcome.Finding;
            why = "ML-DSA enrollment succeeded though GetCACaps advertises no PQ capability (under-advertised / PQ-capable CA)";
        } else {
            // A classical-only CA rejecting ML-DSA is the correct, expected behavior — informational, not a failure.
            outcome = CheckOutcome.Skipped;
            why = "ML-DSA enrollment not accepted (expected for a classical-only CA)";
        }
        report.Results.Add(new CheckResult("probe ML-DSA enrollment", outcome, FailInfo.None, FailInfo.None,
            worked ? PkiStatus.Success : PkiStatus.Failure, why, "spec §14 (empirical PQ probe)", sw.Elapsed));
    }

    // Returns the EnvelopedData *recipient* (encryption-capable cert), not the signing cert, so probe
    // enrollments envelope correctly against split-RA and PQ CAs — matching the enroll/renew path.
    private static ScepResult<X509Certificate2> ResolveCaCert(ScepClient client) {
        ScepResult<System.Collections.Generic.IReadOnlyList<X509Certificate2>> result;
        ScepWright.Core.Recipients.RecipientSelection selection;

        result = client.GetCaCert();
        if (!result.IsOk || result.Value.Count == 0) {
            return ScepResult<X509Certificate2>.Fail(result.IsOk ? ScepClientResult.ServerFailure : result.Status,
                result.IsOk ? "server returned no CA certificate" : result.Error);
        }
        selection = ScepWright.Core.Recipients.RecipientSelector.Select(result.Value);
        if (selection.EncryptionCertificate is null) {
            return ScepResult<X509Certificate2>.Fail(ScepClientResult.ServerFailure, "GetCACert returned no encryption-capable recipient certificate");
        }
        return ScepResult<X509Certificate2>.Ok(selection.EncryptionCertificate);
    }

    // A probe enroll has three outcomes the checks treat differently: it issued (Succeeded), the CA is
    // holding it for manual approval (Pending → inconclusive, SKIP), or it was rejected (Failed).
    private enum ProbeEnroll { Succeeded, Pending, Failed }

    private static ProbeEnroll SubmitEnrollWithKeySpec(ScepClient client, X509Certificate2 ca_cert, string key_spec, string digest, string? challenge) {
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        ScepResult<EnrollOutcome> result;

        builder = ScepRequestBuilder.For(client.Crypto)
            .CaCertificate(ca_cert)
            .MessageType(MessageType.PkcsReq)
            .Subject("CN=probe-" + System.Guid.NewGuid().ToString("N").Substring(0, 8))
            .KeySpec(key_spec)
            .Digest(digest);
        if (challenge != null) { builder.Challenge(challenge); }
        if (!builder.Build(out message, out subject_key, out error)) {
            return ProbeEnroll.Failed;
        }
        result = client.SubmitPkiOperation(message, subject_key, null);
        if (result.Status == ScepClientResult.Pending) { return ProbeEnroll.Pending; }
        return result.IsOk && result.Value?.Certificate != null ? ProbeEnroll.Succeeded : ProbeEnroll.Failed;
    }

    // -------------------------------------------------------------------------
    // Generic step recording
    // -------------------------------------------------------------------------

    private static bool Step(TestReport report, string name, System.Func<bool> action) {
        Stopwatch sw;
        bool ok;

        sw = Stopwatch.StartNew();
        try {
            ok = action();
        } catch (System.Exception) {
            ok = false;
        }
        sw.Stop();
        Record(report, name, ok, ok ? "ok" : "step failed", sw.Elapsed);
        return ok;
    }

    private static void Record(TestReport report, string name, bool ok, string why, System.TimeSpan elapsed) {
        report.Results.Add(new CheckResult(name, ok ? CheckOutcome.Passed : CheckOutcome.Failed,
            FailInfo.None, FailInfo.None, ok ? PkiStatus.Success : PkiStatus.Failure, why, "RFC 8894", elapsed));
    }

    private static void Skip(TestReport report, string name, string why) {
        report.Results.Add(new CheckResult(name, CheckOutcome.Skipped, FailInfo.None, FailInfo.None,
            PkiStatus.Failure, why, "RFC 8894", System.TimeSpan.Zero));
    }
}
