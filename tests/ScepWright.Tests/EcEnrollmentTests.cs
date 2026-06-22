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

public sealed class EcEnrollmentTests {
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    // End-to-end EC subject-key enrollment: an ec:p384 key is signed (ECDSA) into the CSR and the
    // self-signed CMS signer cert, carried over the default RSA recipient profile (so this isolates
    // the EC *subject* key from the recipient/envelope path). The issued certificate must carry an EC
    // public key, and a subsequent renew of that certificate must succeed.
    [Fact]
    public async Task Enroll_ec_subject_key_issues_ec_certificate_and_renews() {
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

        enroll = await client.GetNewCertificateAsync(new EnrollRequest { Subject = "CN=ec-subject", Key = key }, store, log);

        Assert.True(enroll.IsOk, $"{enroll.Status} {enroll.Error}");
        Assert.NotNull(enroll.Value.Certificate);
        Assert.Equal(EcPublicKeyOid, enroll.Value.Certificate!.PublicKey.Oid.Value);

        // A "proper" SCEP renewal signs the renewal request with the stored EC certificate + key
        // (so this reloads the persisted EC private key and ECDSA-signs with it) and, per the existing
        // renewal lifecycle, rolls a fresh subject key for the new cert. Acceptance is that the renew
        // completes successfully; the renewed subject key follows the lifecycle default, not necessarily EC.
        original_id = enroll.Value.Certificate!.Thumbprint.ToLowerInvariant();
        renew = await client.RenewCertificateAsync(original_id, store, log);
        Assert.True(renew.IsOk, $"{renew.Status} {renew.Error}");
        Assert.NotNull(renew.Value.Certificate);
    }
}
