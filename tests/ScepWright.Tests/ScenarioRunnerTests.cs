using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Testing;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Crypto;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class ScenarioRunnerTests {
    [Fact]
    public void Parse_ReadsSteps() {
        string json;
        ScenarioFile scenario;
        string error;

        json = "{ \"name\": \"sweep\", \"steps\": [ { \"name\": \"caps\", \"run\": \"getcacaps\", \"expect\": \"pass\" }, { \"name\": \"md5\", \"run\": \"enroll\", \"args\": { \"digest\": \"MD5\" }, \"expect\": \"badAlg\" } ] }";
        Assert.True(ScenarioRunner.Parse(json, out scenario, out error), error);
        Assert.Equal(2, scenario.Steps.Count);
        Assert.Equal("badAlg", scenario.Steps[1].Expect);
    }

    [Fact]
    public void Parse_RejectsUnknownRunVerb() {
        string json;
        ScenarioFile scenario;
        string error;

        json = "{ \"name\": \"s\", \"steps\": [ { \"name\": \"bad\", \"run\": \"getcacert\", \"expect\": \"pass\" } ] }";
        Assert.False(ScenarioRunner.Parse(json, out scenario, out error));
        Assert.Contains("unknown Run verb 'getcacert'", error);
    }

    [Fact]
    public void Parse_RejectsUnknownExpectToken() {
        ScenarioFile scenario;
        string error;

        Assert.False(ScenarioRunner.Parse("{ \"name\": \"s\", \"steps\": [ { \"name\": \"x\", \"run\": \"enroll\", \"expect\": \"badtypo\" } ] }", out scenario, out error));
        Assert.Contains("unknown Expect", error);
    }

    [Fact]
    public void Parse_RejectsUnknownArgsKey() {
        ScenarioFile scenario;
        string error;

        // 'ndes' isn't a supported Args key — reject it loudly rather than silently ignoring it.
        Assert.False(ScenarioRunner.Parse("{ \"name\": \"s\", \"steps\": [ { \"name\": \"x\", \"run\": \"enroll\", \"args\": { \"ndes\": \"true\" }, \"expect\": \"pass\" } ] }", out scenario, out error));
        Assert.Contains("unknown Args key 'ndes'", error);
    }

    [Fact]
    public async Task Run_AggregatesIntoOneReport() {
        ScepServerApp server;
        ScepClient client;
        ScenarioFile scenario;
        TestReport report;
        string error;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server, out _);
            ScenarioRunner.Parse("{ \"name\": \"s\", \"steps\": [ { \"name\": \"caps\", \"run\": \"getcacaps\", \"expect\": \"pass\" }, { \"name\": \"md5\", \"run\": \"enroll\", \"args\": { \"digest\": \"MD5\" }, \"expect\": \"badAlg\" } ] }", out scenario, out error);
            report = ScenarioRunner.Run(client, scenario, server.Ca.CertificateBcl);
            Assert.Equal("scenario", report.Mode);
            Assert.Equal(2, report.Results.Count);
            Assert.All(report.Results, r => Assert.Equal(CheckOutcome.Passed, r.Outcome));
        } finally {
            await server.DisposeAsync();
        }
    }

    private static ScepClient BuildClientFor(ScepServerApp server, out IScepCrypto crypto) {
        BouncyCastleScepCrypto bc_crypto;
        ScepClient client;

        bc_crypto = new BouncyCastleScepCrypto();
        crypto = bc_crypto;
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, bc_crypto, handler: null, out client, out _);
        return client;
    }
}
