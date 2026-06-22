using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Core.Testing;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class TestEngineModesTests {
    [Fact]
    public async Task Lifecycle_AllStepsRun_MostlyPassed() {
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestEngine engine;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientForWithStore(server, out store, out log);
            engine = new TestEngine();
            report = engine.RunLifecycle(client, store, log);

            Assert.Equal("lifecycle", report.Mode);
            Assert.Contains(report.Results, r => r.Name == "GetCACaps" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "GetCACert" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Passed);
            // enroll succeeded, so renew must run (not Skipped) and GetCRL must run.
            Assert.DoesNotContain(report.Results, r => r.Name == "renew" && r.Outcome == CheckOutcome.Skipped);
            Assert.Contains(report.Results, r => r.Name == "renew" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "GetCRL" && r.Outcome == CheckOutcome.Passed);
            // Mostly PASSED against the fake (no failures expected).
            Assert.Equal(0, report.Failed);
            Assert.Equal(0, report.Skipped);
        } finally {
            await server.DisposeAsync();
        }
    }

    // The lifecycle suite enrolls + renews REAL certs; it must record their footprint.
    [Fact]
    public async Task Lifecycle_records_issued_certificate_footprint() {
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientForWithStore(server, out store, out log);
            report = new TestEngine().RunLifecycle(client, store, log);

            Assert.NotEmpty(report.Footprint);
            Assert.All(report.Footprint, f => Assert.False(string.IsNullOrEmpty(f.Serial)));
        } finally {
            await server.DisposeAsync();
        }
    }

    // The probe suite enrolls REAL certs (SHA-256 / POST probes); it must record their footprint.
    [Fact]
    public async Task Probe_records_issued_certificate_footprint() {
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientForWithStore(server, out store, out log);
            report = new TestEngine().RunProbe(client);

            Assert.NotEmpty(report.Footprint);
            Assert.All(report.Footprint, f => Assert.False(string.IsNullOrEmpty(f.Serial)));
        } finally {
            await server.DisposeAsync();
        }
    }

    // The suite must be able to drive a challenge-protected CA. Without a challenge the
    // enroll is rejected (badRequest); threading the right challenge through RunLifecycle lets it issue.
    [Fact]
    public async Task Lifecycle_against_challenge_ca_passes_only_with_challenge() {
        ScepCa ca;
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestReport without;
        TestReport with;

        ca = ScepCa.Create();
        ca.ExpectedChallenge = "s3cr3t-challenge";
        server = await ScepServerApp.StartAsync(ca);
        try {
            client = BuildClientForWithStore(server, out store, out log);
            without = new TestEngine().RunLifecycle(client, store, log);
            Assert.Contains(without.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Failed);

            client = BuildClientForWithStore(server, out store, out log);
            with = new TestEngine().RunLifecycle(client, store, log, "s3cr3t-challenge");
            Assert.Contains(with.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Passed);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public void Lifecycle_SkipsDownstream_WhenCaCertFails() {
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        TestReport report;

        // Point at an unreachable endpoint so GetCACaps/GetCACert fail; downstream steps must Skip.
        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "dead", Url = new Uri("http://127.0.0.1:1/scep"), PreferPost = true }, crypto, handler: null, out client, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);

        report = new TestEngine().RunLifecycle(client, store, log);

        Assert.Contains(report.Results, r => r.Name == "GetCACert" && r.Outcome == CheckOutcome.Failed);
        Assert.Contains(report.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Skipped);
        Assert.Contains(report.Results, r => r.Name == "renew" && r.Outcome == CheckOutcome.Skipped);
        Assert.Contains(report.Results, r => r.Name == "GetCRL" && r.Outcome == CheckOutcome.Skipped);
    }

    // --dry-run runs only the read-only checks (caps, cacert, recipient verdict,
    // GetNextCACert) and issues NOTHING — so it is safe to point at a CA you don't own.
    [Fact]
    public async Task DryRun_RunsReadOnlyChecks_AndIssuesNothing() {
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientForWithStore(server, out store, out log);
            report = new TestEngine().RunDryRun(client);

            Assert.Equal("dry-run", report.Mode);
            Assert.Contains(report.Results, r => r.Name == "GetCACaps" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "GetCACert" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name.Contains("recipient") && r.Outcome == CheckOutcome.Passed);
            // No enrolling/renewing steps at all.
            Assert.DoesNotContain(report.Results, r => r.Name == "enroll");
            Assert.DoesNotContain(report.Results, r => r.Name == "renew");
            Assert.Equal(0, report.Failed);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Probe_Sha256_And_Post_Work() {
        ScepServerApp server;
        ScepClient client;
        TestReport report;
        CheckResult sha256;
        CheckResult post;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            report = new TestEngine().RunProbe(client);

            Assert.Equal("probe", report.Mode);

            sha256 = report.Results.First(r => r.Name.Contains("SHA-256"));
            // The fake advertises SHA-256, so a working SHA-256 enroll is PASSED.
            Assert.Equal(CheckOutcome.Passed, sha256.Outcome);

            post = report.Results.First(r => r.Name.Contains("POST"));
            // The fake advertises POSTPKIOperation and the client posts -> PASSED.
            Assert.Equal(CheckOutcome.Passed, post.Outcome);

            // The fake's GET handler does not know GetNextCACert -> FAILED, but it must not crash.
            Assert.Contains(report.Results, r => r.Name.Contains("GetNextCACert"));
        } finally {
            await server.DisposeAsync();
        }
    }

    // A PENDING-mode CA holds every request for manual approval, so the probe's enroll-based checks
    // (SHA-256, POST) can't be assessed — that's SKIPPED, not a FAILED enrollment.
    [Fact]
    public async Task Probe_against_pending_ca_skips_enroll_checks() {
        ScepCa ca;
        ScepServerApp server;
        ScepClient client;
        TestReport report;
        CheckResult sha256;
        CheckResult post;

        ca = ScepCa.Create();
        ca.PendingMode = true;
        server = await ScepServerApp.StartAsync(ca);
        try {
            client = BuildClientFor(server);
            report = new TestEngine().RunProbe(client);

            sha256 = report.Results.First(r => r.Name.Contains("SHA-256"));
            Assert.Equal(CheckOutcome.Skipped, sha256.Outcome);

            post = report.Results.First(r => r.Name.Contains("POST"));
            Assert.Equal(CheckOutcome.Skipped, post.Outcome);

            // PENDING must never read as a hard failure.
            Assert.DoesNotContain(report.Results, r => (r.Name.Contains("SHA-256") || r.Name.Contains("POST")) && r.Outcome == CheckOutcome.Failed);
        } finally {
            await server.DisposeAsync();
        }
    }

    // The coverage matrix documents a lifecycle "poll" check. It is emitted only when the CA returns
    // PENDING (a normal CA issues immediately, so there is nothing to poll). Against a PENDING-mode CA the
    // enroll must read as SKIPPED (held for approval), NOT Passed, and a "poll" row MUST appear.
    [Fact]
    public async Task Lifecycle_against_pending_ca_emits_poll_and_skips_enroll() {
        ScepCa ca;
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        TestReport report;

        ca = ScepCa.Create();
        ca.PendingMode = true;
        server = await ScepServerApp.StartAsync(ca);
        try {
            client = BuildClientForWithStore(server, out store, out log);
            report = new TestEngine().RunLifecycle(client, store, log);

            Assert.Contains(report.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Skipped);
            Assert.DoesNotContain(report.Results, r => r.Name == "enroll" && r.Outcome == CheckOutcome.Passed);
            Assert.Contains(report.Results, r => r.Name == "poll");
        } finally {
            await server.DisposeAsync();
        }
    }

    private static ScepClient BuildClientFor(ScepServerApp server) {
        BouncyCastleScepCrypto crypto;
        ScepClient client;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }

    private static ScepClient BuildClientForWithStore(ScepServerApp server, out CertStore store, out UseRecordLog log) {
        string root;
        ScepClient client;

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);
        client = BuildClientFor(server);
        return client;
    }
}
