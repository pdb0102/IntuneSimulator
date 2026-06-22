using System;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class FaultMatrixServerTests {
    [Fact]
    public async Task CorruptSignature_YieldsBadMessageCheck() {
        await RunFault(new FaultDirectives { CorruptSignature = true }, FailInfo.BadMessageCheck);
    }

    [Fact]
    public async Task SkewedSigningTime_YieldsBadTime() {
        await RunFault(new FaultDirectives { SigningTimeSkew = TimeSpan.FromHours(2) }, FailInfo.BadTime);
    }

    [Fact]
    public async Task CorruptInner_YieldsBadRequest() {
        await RunFault(new FaultDirectives { CorruptInnerContent = true }, FailInfo.BadRequest);
    }

    [Fact]
    public async Task Md5Digest_YieldsBadAlg() {
        await RunDigestFault("MD5", FailInfo.BadAlg);
    }

    private static async Task RunFault(FaultDirectives faults, FailInfo expected) {
        ScepServerApp server;
        ScepClient client;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        ScepResult<EnrollOutcome> result;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            ScepRequestBuilder.For(client.Crypto)
                .CaCertificate(server.Ca.CertificateBcl)
                .MessageType(MessageType.PkcsReq)
                .Subject("CN=fault-client")
                .KeySpec("rsa:2048")
                .AllowFaults(faults)
                .Build(out message, out subject_key, out error);
            Assert.NotNull(message);

            result = client.SubmitPkiOperation(message, subject_key, faults);
            Assert.Equal(PkiStatus.Failure, result.Value.PkiStatus);
            Assert.Equal(expected, result.Value.FailInfo);
        } finally {
            await server.DisposeAsync();
        }
    }

    private static async Task RunDigestFault(string digest, FailInfo expected) {
        ScepServerApp server;
        ScepClient client;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        ScepResult<EnrollOutcome> result;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientFor(server);
            ScepRequestBuilder.For(client.Crypto)
                .CaCertificate(server.Ca.CertificateBcl)
                .MessageType(MessageType.PkcsReq)
                .Subject("CN=fault-client")
                .KeySpec("rsa:2048")
                .Digest(digest)
                .Build(out message, out subject_key, out error);
            Assert.NotNull(message);

            result = client.SubmitPkiOperation(message, subject_key, null);
            Assert.Equal(PkiStatus.Failure, result.Value.PkiStatus);
            Assert.Equal(expected, result.Value.FailInfo);
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
