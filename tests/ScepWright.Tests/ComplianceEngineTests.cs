using System.Linq;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Protocol;
using ScepWright.Core.Testing;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class ComplianceEngineTests {
    [Fact]
    public async Task RunFull_ProducesExpectedOutcomes() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        ComplianceEngine engine;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            engine = new ComplianceEngine();
            report = engine.RunFull(client, client.GetCaCert().Value, caps);

            Assert.Equal("full", report.Mode);
            // The five well-defined failInfo rows pass against the fake:
            Assert.Equal(CheckOutcome.Passed, Find(report, "forbidden algorithm (MD5)").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "corrupted CMS signature").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "signingTime skew (+2h)").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "GetCert unknown serial").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "malformed PKCS#10").Outcome);
            // The fake handles renewal though caps omit Renewal -> a finding, not a failure.
            Assert.Equal(CheckOutcome.Finding, Find(report, "RenewalReq when not advertised").Outcome);
        } finally {
            await server.DisposeAsync();
        }
    }

    // Against a split-RA / PQ CA the signing cert (ML-DSA here) cannot be
    // the EnvelopedData recipient. RunFull must select the RA encryption cert from the bundle (like
    // enroll/renew) while still using the CA signing-cert subject as the GetCert issuer DN. Before the
    // fix every enroll-based negative check CryptoErrored on the ML-DSA recipient and came back Failed.
    [Fact]
    public async Task RunFull_against_pq_split_ca_envelopes_to_ra_recipient() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        ComplianceEngine engine;
        TestReport report;

        server = await ScepServerApp.StartAsync(ScepCa.CreateWithRaEncryption("rsa", "ml-dsa"));
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            engine = new ComplianceEngine();
            report = engine.RunFull(client, client.GetCaCert().Value, caps);

            // The MD5 request reaches the server and is rejected with badAlg only if it was enveloped to
            // the RSA RA cert; against the ML-DSA signing cert the request never encodes (CryptoError).
            Assert.Equal(CheckOutcome.Passed, Find(report, "forbidden algorithm (MD5)").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "corrupted CMS signature").Outcome);
            Assert.Equal(CheckOutcome.Passed, Find(report, "malformed PKCS#10").Outcome);
            // GetCert uses the CA signing-cert subject as the issuer DN (its own enveloping is internal).
            Assert.Equal(CheckOutcome.Passed, Find(report, "GetCert unknown serial").Outcome);
            // Nothing should fail for an un-enveloped (ML-DSA recipient) reason.
            Assert.DoesNotContain(report.Results, r => r.Why.Contains("ML-DSA") || r.Why.Contains("unknown-algorithm"));
        } finally {
            await server.DisposeAsync();
        }
    }

    // Against a challenge-protected CA with NO challenge, every PKCSReq is rejected
    // uniformly, so all the NEGATIVE checks score PASS and the suite goes green — proving nothing. A
    // positive-control baseline enroll must FAIL loudly (naming the missing challenge) so CI can't pass.
    [Fact]
    public async Task RunFull_against_challenge_ca_without_challenge_is_not_silently_green() {
        ScepCa ca;
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport without;
        TestReport with;

        ca = ScepCa.Create();
        ca.ExpectedChallenge = "s3cret";
        server = await ScepServerApp.StartAsync(ca);
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;

            without = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);
            Assert.True(without.Failed > 0, "omitted challenge against a challenge CA must not be all-green");
            Assert.Contains(without.Results, r => r.Outcome == CheckOutcome.Failed && r.Why.Contains("challenge"));

            with = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps, "s3cret");
            Assert.Contains(with.Results, r => r.Name.Contains("baseline") && r.Outcome == CheckOutcome.Passed);
            Assert.Equal(0, with.Failed);
        } finally {
            await server.DisposeAsync();
        }
    }

    // Nothing verified the server echoes our senderNonce back as recipientNonce
    // (RFC 8894 §3.2.1.1). The fake CA echoes correctly, so the check must PASS.
    [Fact]
    public async Task RunFull_verifies_recipient_nonce_echo() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            report = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);

            Assert.Equal(CheckOutcome.Passed, Find(report, "recipientNonce echo").Outcome);
        } finally {
            await server.DisposeAsync();
        }
    }

    // A server with no anti-replay re-issues for a byte-identical (same senderNonce/transId)
    // PKIMessage. The fake has no replay protection, so re-sending the same bytes succeeds twice -> a
    // leniency Finding (more permissive than the RFC nonce mechanism intends).
    [Fact]
    public async Task RunFull_flags_replayed_request_as_finding() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            report = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);

            Assert.Equal(CheckOutcome.Finding, Find(report, "replayed PKIMessage").Outcome);
        } finally {
            await server.DisposeAsync();
        }
    }

    // The suite never flagged a server that accepts a weak content-encryption algorithm.
    // The fake decrypts a 3DES-enveloped request and issues -> a leniency Finding.
    [Fact]
    public async Task RunFull_flags_weak_content_encryption_as_finding() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            report = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);

            Assert.Equal(CheckOutcome.Finding, Find(report, "weak content-encryption (3DES)").Outcome);
        } finally {
            await server.DisposeAsync();
        }
    }

    // The suite never flagged a server that issues for an arbitrary/unauthorized subject.
    // The fake honors any subject -> a leniency Finding (acceptable for an open test CA; a production
    // RA should bind the subject to the authenticated principal).
    [Fact]
    public async Task RunFull_flags_arbitrary_subject_as_finding() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            report = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);

            Assert.Equal(CheckOutcome.Finding, Find(report, "arbitrary subject (no authorization)").Outcome);
        } finally {
            await server.DisposeAsync();
        }
    }

    // Live suites mint REAL certs with only a printed warning — no list for cleanup/revocation.
    // RunFull must record a footprint of every certificate it caused the CA to issue (serial + subject).
    [Fact]
    public async Task RunFull_records_issued_certificate_footprint() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            report = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);

            Assert.NotEmpty(report.Footprint);
            Assert.All(report.Footprint, f => Assert.False(string.IsNullOrEmpty(f.Serial)));
            Assert.All(report.Footprint, f => Assert.False(string.IsNullOrEmpty(f.Subject)));
        } finally {
            await server.DisposeAsync();
        }
    }

    // Against a CA that cannot issue at all (an ML-DSA-only CA: no encryption-capable
    // recipient, so no enroll request can even be enveloped/sent), every enroll-based negative check
    // gets NO SCEP response. The classifier must NOT read "no response" as "server rejected as
    // expected -> Passed" for the Expected==None checks, or the written audit evidence lies (claims the
    // CA "enforces AES" / "enforces subject authorization" against a CA that issues nothing). They must
    // be Skipped/Inconclusive, and the positive-control baseline must still FAIL loudly.
    [Fact]
    public async Task RunFull_against_unissuable_ca_does_not_falsely_pass_negative_checks() {
        ScepServerApp server;
        ScepClient client;
        ScepCapabilities caps;
        TestReport report;

        server = await ScepServerApp.StartAsync(ScepCa.Create("ml-dsa"));
        try {
            client = BuildClientFor(server);
            caps = client.GetCaCaps().Value;
            report = new ComplianceEngine().RunFull(client, client.GetCaCert().Value, caps);

            // The CA can't issue, so the baseline positive control must FAIL (drives a non-zero exit).
            Assert.Equal(CheckOutcome.Failed, Find(report, "baseline enrollment (positive control)").Outcome);
            // No enroll request reached the server, so these Expected==None checks must be inconclusive,
            // NOT a false "rejected as expected -> Passed".
            Assert.Equal(CheckOutcome.Skipped, Find(report, "wrong challenge password").Outcome);
            Assert.Equal(CheckOutcome.Skipped, Find(report, "weak content-encryption (3DES)").Outcome);
            Assert.Equal(CheckOutcome.Skipped, Find(report, "arbitrary subject (no authorization)").Outcome);
            Assert.Equal(CheckOutcome.Skipped, Find(report, "RenewalReq when not advertised").Outcome);
            // Nothing may be reported as Passed when no request could be sent.
            Assert.DoesNotContain(report.Results, r => r.Outcome == CheckOutcome.Passed);
        } finally {
            await server.DisposeAsync();
        }
    }

    private static CheckResult Find(TestReport report, string name) =>
        report.Results.First(r => r.Name == name);

    private static ScepClient BuildClientFor(ScepServerApp server) {
        BouncyCastleScepCrypto crypto;
        ScepClient client;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }
}
