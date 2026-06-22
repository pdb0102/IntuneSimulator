using System.IO;
using System.Security.Cryptography.X509Certificates;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class EncryptedKeyTests {
    [Fact]
    public void Encrypted_pkcs8_round_trips() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        byte[] enc;
        IScepKey imported;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        Assert.True(crypto.ExportPrivateKeyPkcs8Encrypted(key, "s3cret", out enc, out _));
        Assert.True(crypto.ImportPrivateKeyPkcs8Encrypted(enc, "s3cret", out imported, out string err), err);
        Assert.Equal(2048, imported.SizeBits);
        Assert.False(crypto.ImportPrivateKeyPkcs8Encrypted(enc, "wrong", out _, out _));
    }

    [Fact]
    public void Encrypted_pkcs8_uses_pbes2_aes256_sha256() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        byte[] enc;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        Assert.True(crypto.ExportPrivateKeyPkcs8Encrypted(key, "s3cret", out enc, out _));

        Assert.True(ContainsOid(enc, "1.2.840.113549.1.5.13"), "should be PBES2");
        Assert.True(ContainsOid(enc, "2.16.840.1.101.3.4.1.42"), "should use AES-256-CBC");
        Assert.True(ContainsOid(enc, "1.2.840.113549.2.9"), "should use HMAC-SHA256 PRF");
        Assert.False(ContainsOid(enc, "1.2.840.113549.1.12.1.3"), "must NOT be legacy PBES1 SHA1+3DES");
    }

    private static bool ContainsOid(byte[] haystack, string oid) {
        byte[] needle;
        int i;
        int j;

        needle = new Org.BouncyCastle.Asn1.DerObjectIdentifier(oid).GetEncoded();
        for (i = 0; i + needle.Length <= haystack.Length; i++) {
            for (j = 0; j < needle.Length; j++) {
                if (haystack[i + j] != needle[j]) { break; }
            }
            if (j == needle.Length) { return true; }
        }
        return false;
    }

    [Fact]
    public void Store_writes_encrypted_key_file() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        X509Certificate2 cert;
        string root;
        CertStore store;
        string cert_id;
        IScepKey loaded_key;
        string cert_dir;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        cert = new X509Certificate2(ca.Issue(((BcKey)key).KeyPair.Public, "CN=poodle").GetEncoded());

        root = Directory.CreateTempSubdirectory().FullName;
        store = new CertStore(root);
        cert_id = store.Save("fake", cert, key, crypto, challenge_password: null, renewed_from: null, transaction_id: null, passphrase: "s3cret");

        cert_dir = Path.Combine(root, "servers", "fake", "certificates", cert_id);
        Assert.True(File.Exists(Path.Combine(cert_dir, "key.pkcs8.enc")));
        Assert.False(File.Exists(Path.Combine(cert_dir, "key.pkcs8")));

        Assert.True(store.Load("fake", cert_id, crypto, out _, out loaded_key, out _, out string err, passphrase: "s3cret"), err);
        Assert.Equal(2048, loaded_key.SizeBits);
    }
}
