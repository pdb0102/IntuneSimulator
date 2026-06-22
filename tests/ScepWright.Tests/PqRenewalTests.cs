using System.IO;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Protocol;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

// PQ renewal 500'd server-side. On a proper RenewalReq the message is signed by the
// existing (ML-DSA, signature-only) cert, so the server tried to envelope the CertRep back to a key
// that cannot receive one and threw with no try/catch → HTTP 500.
public sealed class PqRenewalTests {
    // Server fix: an un-envelopable recipient must yield a clean SCEP failInfo, never a 500/NetworkError.
    [Fact]
    public async Task Pq_proper_renew_returns_clean_failinfo_not_500() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        KeySpec spec;
        IScepKey key;
        string error;
        ScepResult<EnrollOutcome> enroll;
        string cert_id;
        ScepResult<EnrollOutcome> renew;

        server = await ScepServerApp.StartAsync(ScepCa.Create());
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pq", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;
            store = new CertStore(root);
            log = new UseRecordLog(root);

            Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);
            enroll = client.GetNewCertificate(new EnrollRequest { Subject = "CN=pq-renew", Key = key }, store, log);
            Assert.True(enroll.IsOk, $"enroll: {enroll.Status} {enroll.Error}");
            cert_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();

            // A proper RenewalReq is signed by the existing ML-DSA cert, which can't receive the envelope.
            // The server must answer with a failInfo (clean SCEP failure), not crash with a 500.
            renew = client.RenewCertificate(cert_id, store, log);
            Assert.False(renew.IsOk);
            Assert.NotEqual(ScepClientResult.NetworkError, renew.Status);
        } finally {
            await server.DisposeAsync();
        }
    }

    // Reenroll-same-subject renewal of a PQ cert against a split/PQ CA CryptoErrored
    // because the renewal path enveloped to the CA *signing* cert (ML-DSA) instead of the RA encryption
    // cert. Renew must resolve the RA recipient itself (like enroll) when none is supplied.
    [Fact]
    public async Task Reenroll_same_subject_against_pq_split_ca_resolves_ra_recipient() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        KeySpec spec;
        IScepKey key;
        string error;
        ScepResult<EnrollOutcome> enroll;
        ScepResult<EnrollOutcome> renew;

        // ML-DSA signing CA + RSA RA encryption cert (the mldsa-rsa split shape).
        server = await ScepServerApp.StartAsync(ScepCa.CreateWithRaEncryption("rsa", "ml-dsa"));
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pq", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;
            store = new CertStore(root);
            log = new UseRecordLog(root);

            Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);
            enroll = client.GetNewCertificate(new EnrollRequest { Subject = "CN=pq-reenroll", Key = key }, store, log);
            Assert.True(enroll.IsOk, $"enroll: {enroll.Status} {enroll.Error}");

            // CaCertificate left null -> the client must select the RA encryption cert, not Value[0].
            renew = client.Renew(new RenewRequest {
                Subject = "CN=pq-reenroll",
                ExistingCertificate = enroll.Value.Certificate!,
                ExistingKey = key,
                Variant = RenewalVariant.ReenrollSameSubject,
                KeySpecText = "ml-dsa:65",
            });
            Assert.True(renew.IsOk, $"reenroll: {renew.Status} {renew.Error}");
            Assert.NotNull(renew.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }

    // Builder fix: a self-signed PKCSReq with a PQ signature subject key must use a transient RSA
    // transport key (like enroll) so the CertRep can be enveloped back — this is the path the
    // reenroll-same-subject renewal variant and the PQ probe take.
    [Fact]
    public async Task Self_signed_pq_pkcsreq_uses_transient_transport_and_succeeds() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        ScepResult<EnrollOutcome> result;

        server = await ScepServerApp.StartAsync(ScepCa.Create());
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pq", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);

            builder = ScepRequestBuilder.For(crypto)
                .CaCertificate(client.GetCaCert().Value[0])
                .MessageType(MessageType.PkcsReq)
                .Subject("CN=pq-self")
                .KeySpec("ml-dsa:65");
            Assert.True(builder.Build(out message, out subject_key, out error), error);

            result = client.SubmitPkiOperation(message, subject_key, null);
            Assert.True(result.IsOk, $"{result.Status} {result.Error}");
            Assert.NotNull(result.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }
}
