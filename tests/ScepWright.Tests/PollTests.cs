using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class PollTests {
    [Fact]
    public async Task Poll_returns_a_cert_for_the_subject() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

        result = await client.PollAsync(server.Ca.Certificate.SubjectDN.ToString(), "CN=poodle", "txn-123");
        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
        Assert.Equal("txn-123", result.Value.TransactionId);
    }
}
