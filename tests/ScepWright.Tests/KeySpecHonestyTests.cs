using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

// Key-spec honesty audit: enrollment must record the exact key-spec used, and a renewal
// (without an explicit override) must preserve the renewed certificate's algorithm rather
// than silently forcing rsa:2048.
public sealed class KeySpecHonestyTests {
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    // ML-KEM is a key-encapsulation algorithm, not a signature scheme, so it can never be a
    // certificate subject key. KeySpec.Parse must reject it up front with a clear message rather than
    // mint a doomed key that only fails later at enroll. (ML-KEM remains valid as a recipient/encryption
    // algorithm — that path does not go through KeySpec.)
    [Theory]
    [InlineData("ml-kem:512")]
    [InlineData("ml-kem:768")]
    [InlineData("ml-kem:1024")]
    public void Parse_rejects_ml_kem_as_subject_key(string text) {
        KeySpec spec;
        string error;

        Assert.False(KeySpec.Parse(text, out spec, out error));
        Assert.Contains("ML-KEM", error);
        Assert.Contains("subject", error.ToLowerInvariant());
    }

    // Enrolling with an explicit EC subject key must persist KeySpec on the stored CertRecord,
    // so that downstream consumers (renew, audits) can see the algorithm actually used.
    [Fact]
    public async Task Enroll_records_keyspec_on_certrecord() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
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
        RecordProbe probe;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "ec", Url = server.ProfileUrl("rsa"), PreferPost = true }, crypto, handler: null, out client, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);

        Assert.True(KeySpec.Parse("ec:p384", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);

        enroll = await client.GetNewCertificateAsync(
            new EnrollRequest { Subject = "CN=ec-record", Key = key, KeySpecText = "ec:p384" }, store, log);
        Assert.True(enroll.IsOk, $"{enroll.Status} {enroll.Error}");
        Assert.NotNull(enroll.Value.Certificate);

        cert_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();
        probe = RecordProbe.Load(store, "ec", cert_id, crypto);
        Assert.Equal("ec:p384", probe.Record.KeySpec);
    }

    // A "proper" renewal of an EC-enrolled certificate, with no --key-spec override, must roll a
    // fresh EC subject key (preserving the cert's algorithm) — not silently fall back to RSA.
    [Fact]
    public async Task Renew_preserves_certificate_algorithm() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        CertStore store;
        UseRecordLog log;
        KeySpec spec;
        IScepKey key;
        string error;
        ScepResult<EnrollOutcome> enroll;
        string original_id;
        ScepResult<EnrollOutcome> renew;

        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "ec", Url = server.ProfileUrl("rsa"), PreferPost = true }, crypto, handler: null, out client, out _);
        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        log = new UseRecordLog(root);

        Assert.True(KeySpec.Parse("ec:p384", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);

        enroll = await client.GetNewCertificateAsync(
            new EnrollRequest { Subject = "CN=ec-renew", Key = key, KeySpecText = "ec:p384" }, store, log);
        Assert.True(enroll.IsOk, $"{enroll.Status} {enroll.Error}");
        Assert.NotNull(enroll.Value.Certificate);
        Assert.Equal(EcPublicKeyOid, enroll.Value.Certificate!.PublicKey.Oid.Value);

        original_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();
        renew = await client.RenewCertificateAsync(original_id, store, log);
        Assert.True(renew.IsOk, $"{renew.Status} {renew.Error}");
        Assert.NotNull(renew.Value.Certificate);
        Assert.Equal(EcPublicKeyOid, renew.Value.Certificate!.PublicKey.Oid.Value);
    }

    private sealed class RecordProbe {
        public CertStore.CertRecord Record { get; private init; } = null!;

        public static RecordProbe Load(CertStore store, string server_id, string cert_id, IScepCrypto crypto) {
            CertStore.CertRecord record;
            string load_error;

            Assert.True(store.Load(server_id, cert_id, crypto, out _, out _, out record, out load_error), load_error);
            return new RecordProbe { Record = record };
        }
    }
}
