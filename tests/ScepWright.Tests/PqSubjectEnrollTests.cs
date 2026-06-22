using System.IO;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Crypto;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class PqSubjectEnrollTests {
    private const string MlDsa65Oid = "2.16.840.1.101.3.4.3.18";

    // (b) The realistic PQ enrollment: the certified key is ML-DSA, carried over an RSA-signed/decrypted
    // SCEP transport (a transient RSA key is generated for the envelope because a PQ signature key
    // cannot decrypt the CertRep). The issued certificate carries the ML-DSA subject key.
    [Fact]
    public async Task Enroll_pq_subject_key_issues_pq_certificate() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await ScepServerApp.StartAsync();
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

    // (a) A self-signed PKCSReq with an ML-DSA subject key cannot itself decrypt the CertRep, so the
    // builder transparently signs with a transient RSA transport key (the same bridge the enroll path
    // uses). The exchange now completes and the issued certificate still carries the ML-DSA subject key.
    // (The genuinely-impossible case — an *explicit* PQ signer cert, i.e. a proper RenewalReq — is
    // covered by PqRenewalTests, where a conformant server now answers with a clean failInfo, not a 500.)
    [Fact]
    public async Task Self_signed_pq_request_completes_via_transient_transport() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        ScepResult<System.Collections.Generic.IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2>> ca;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        byte[] der;
        ScepResult<EnrollOutcome> result;

        server = await ScepServerApp.StartAsync();
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pqprobe", Url = server.ProfileUrl("rsa"), PreferPost = true }, crypto, handler: null, out client, out _);
            ca = client.GetCaCert();
            Assert.True(ca.IsOk, ca.Error);

            builder = ScepRequestBuilder.For(crypto)
                .CaCertificate(ca.Value[0])
                .MessageType(ScepWright.Crypto.MessageType.PkcsReq)
                .Subject("CN=pure-pq")
                .KeySpec("ml-dsa:65");                 // PQ subject key, self-signed -> transient RSA transport
            Assert.True(builder.Build(out message, out subject_key, out error), error);

            // The request encodes (the client can emit it).
            Assert.True(message.Encode(crypto, out der, out error), error);
            Assert.True(der.Length > 0);

            // The exchange completes via the transient RSA transport key, and the issued cert is ML-DSA.
            result = client.SubmitPkiOperation(message, subject_key, null);
            Assert.True(result.IsOk, $"{result.Status} {result.Error}");
            Assert.Equal(MlDsa65Oid, result.Value.Certificate!.GetKeyAlgorithm());
        } finally {
            await server.DisposeAsync();
        }
    }
}
