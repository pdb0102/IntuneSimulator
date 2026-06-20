using System.IO;
using System.Threading.Tasks;
using ScepTestClient.Core;
using ScepTestClient.Core.Storage;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqSubjectEnrollTests {
    private const string MlDsa65Oid = "2.16.840.1.101.3.4.3.18";

    // (b) The realistic PQ enrollment: the certified key is ML-DSA, carried over an RSA-signed/decrypted
    // SCEP transport (a transient RSA key is generated for the envelope because a PQ signature key
    // cannot decrypt the CertRep). The issued certificate carries the ML-DSA subject key.
    [Fact]
    public async Task Enroll_pq_subject_key_issues_pq_certificate() {
        FakeScepServer server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await FakeScepServer.StartAsync();
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pq", Url = server.ProfileUrl("rsa"), PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=pq-subject", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            Assert.True(outcome.IsOk, $"{outcome.Status} {outcome.Error}");
            Assert.NotNull(outcome.Value.Certificate);
            Assert.Equal(MlDsa65Oid, outcome.Value.Certificate!.GetKeyAlgorithm());
        } finally {
            await server.DisposeAsync();
        }
    }

    // (a) Conformance probe: the client CAN emit a fully PQ-signed request (ML-DSA outer signature),
    // but a server cannot return the CertRep (it can't envelope the response back to an ML-DSA signing
    // key) — so the exchange fails, which is the correct outcome to observe.
    [Fact]
    public async Task Pure_pq_signed_request_is_emitted_but_exchange_cannot_complete() {
        FakeScepServer server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        byte[] der;
        ScepResult<EnrollOutcome> result;

        server = await FakeScepServer.StartAsync();
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pqprobe", Url = server.ProfileUrl("rsa"), PreferPost = true }, crypto, handler: null, out client, out _);
            ca = client.GetCaCert();
            Assert.True(ca.IsOk, ca.Error);

            builder = ScepRequestBuilder.For(crypto)
                .CaCertificate(ca.Value[0])
                .MessageType(ScepTestClient.CryptoApi.MessageType.PkcsReq)
                .Subject("CN=pure-pq")
                .KeySpec("ml-dsa:65");                 // subject == signer -> PQ outer signature
            Assert.True(builder.Build(out message, out subject_key, out error), error);

            // The PQ-signed request encodes (the client can emit it).
            Assert.True(message.Encode(crypto, out der, out error), error);
            Assert.True(der.Length > 0);

            // But the server cannot complete the exchange (cannot envelope the response to an ML-DSA key).
            result = client.SubmitPkiOperation(message, subject_key, null);
            Assert.False(result.IsOk);
        } finally {
            await server.DisposeAsync();
        }
    }
}
