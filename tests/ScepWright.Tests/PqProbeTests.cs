using System.Linq;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Testing;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class PqProbeTests {
    [Fact]
    public async Task Probe_includes_ml_dsa_row() {
        ScepServerApp server;
        ScepClient client;
        TestReport report;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            report = new TestEngine().RunProbe(client);

            // The PQ row must exist and must never be FAILED: a classical-only CA rejecting ML-DSA is
            // expected (Skipped/Info), and a PQ-capable CA accepting it is a Finding — neither is a failure.
            Assert.Contains(report.Results, r => r.Name.Contains("ML-DSA"));
            Assert.DoesNotContain(report.Results, r => r.Name.Contains("ML-DSA") && r.Outcome == CheckOutcome.Failed);
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
}
