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

// End-to-end: the client must parse the GetCACert bundle, select the encryption cert by KeyUsage,
// and envelope the request to it (not blindly to the first / CA signing cert).
public sealed class SplitCertEnrollTests {
    [Fact]
    public async Task Enroll_through_separate_ra_encryption_cert_succeeds() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await ScepServerApp.StartAsync(ScepCa.CreateWithRaEncryption());
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "split", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=split-enroll", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            // Succeeds only if the client enveloped to the RA encryption cert: the CA/signing cert
            // lacks keyEncipherment, and the server decrypts with the separate RA key.
            Assert.True(outcome.IsOk, $"{outcome.Status} {outcome.Error}");
            Assert.NotNull(outcome.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Enroll_against_signing_only_ca_fails_with_conformance_finding() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await ScepServerApp.StartAsync(ScepCa.CreateSigningOnly());
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "signonly", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=signonly-enroll", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            // The server's only cert lacks keyEncipherment, so the request cannot be enveloped.
            Assert.False(outcome.IsOk);
            Assert.Contains("envelop", outcome.Error);
        } finally {
            await server.DisposeAsync();
        }
    }

    // Regression: renew + GetCRL must envelope to the RA encryption cert (like enroll), not the CA
    // signing cert. Against a PQ CA the signing cert is ML-DSA, which cannot be an encryption recipient,
    // so the whole lifecycle previously broke with a CryptoError.
    [Fact]
    public async Task Renew_and_getcrl_through_pq_ca_use_ra_recipient() {
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
        string cert_id;
        ScepResult<byte[]> crl;

        // ML-DSA signing CA + RSA RA encryption cert (the "mldsa-rsa" profile shape).
        server = await ScepServerApp.StartAsync(ScepCa.CreateWithRaEncryption("rsa", "ml-dsa"));
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "pq", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;
            store = new CertStore(root);
            log = new UseRecordLog(root);

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);
            enroll = client.GetNewCertificate(new EnrollRequest { Subject = "CN=pq-lifecycle", Key = key }, store, log);
            Assert.True(enroll.IsOk, $"enroll: {enroll.Status} {enroll.Error}");
            cert_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();

            // Renew must succeed — it envelopes to the RSA RA cert, not the ML-DSA signing cert.
            renew = client.RenewCertificate(cert_id, store, log);
            Assert.True(renew.IsOk, $"renew: {renew.Status} {renew.Error}");

            // GetCRL must at least get past enveloping (no CryptoError from an ML-DSA recipient).
            crl = client.GetCrl(client.GetCaCert().Value[0].Subject, "01");
            Assert.NotEqual(ScepClientResult.CryptoError, crl.Status);
        } finally {
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Enroll_through_ec_key_agreement_ra_cert_succeeds() {
        ScepServerApp server;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        string error;
        EnrollRequest request;
        ScepResult<EnrollOutcome> outcome;

        server = await ScepServerApp.StartAsync(ScepCa.CreateWithRaEncryption("ec"));
        try {
            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "ec", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            Assert.True(KeySpec.Parse("rsa:2048", out spec, out error), error);
            Assert.True(crypto.GenerateKey(spec, out key, out error), error);

            request = new EnrollRequest { Subject = "CN=ec-enroll", Key = key };
            outcome = client.GetNewCertificate(request, new CertStore(root), new UseRecordLog(root));

            // Succeeds only if the client enveloped to the EC RA cert via ECDH key agreement and the
            // server decrypted with the EC private key.
            Assert.True(outcome.IsOk, $"{outcome.Status} {outcome.Error}");
            Assert.NotNull(outcome.Value.Certificate);
        } finally {
            await server.DisposeAsync();
        }
    }
}
