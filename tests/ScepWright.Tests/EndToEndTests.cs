using System;
using System.IO;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class EndToEndTests {
    [Fact]
    public async Task Gets_a_certificate_end_to_end_async() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        EnrollRequest request;
        string root;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.Equal(ScepClientResult.Ok, ScepClient.Create(
            new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null,
            out client, out _));

        request = new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw" };
        root = Directory.CreateTempSubdirectory().FullName;
        result = await client.GetNewCertificateAsync(request, new CertStore(root), new UseRecordLog(root));

        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
        Assert.Contains("poodle", result.Value.Certificate!.Subject);
    }

    [Fact]
    public async Task Gets_a_certificate_end_to_end_sync() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        ScepClient client;
        EnrollRequest request;
        string root;
        ScepResult<EnrollOutcome> result;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        request = new EnrollRequest { Subject = "CN=poodle", Key = key, ChallengePassword = "pw" };
        root = Directory.CreateTempSubdirectory().FullName;

        result = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));
        Assert.True(result.IsOk, result.Error);
        Assert.NotNull(result.Value.Certificate);
    }
}
