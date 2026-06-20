using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqKeyGenTests {
    [Theory]
    [InlineData("ml-dsa:65", "2.16.840.1.101.3.4.3.18")]
    [InlineData("ml-dsa:87", "2.16.840.1.101.3.4.3.19")]
    [InlineData("slh-dsa:128s", "2.16.840.1.101.3.4.3.20")]
    public void Generates_pq_key(string key_spec, string expected_oid) {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse(key_spec, out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        Assert.Equal(expected_oid, key.AlgorithmOid);
    }

    [Fact]
    public void Pkcs8_roundtrip_ml_dsa() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        IScepKey imported;
        byte[] der;
        byte[] der2;
        string error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);
        Assert.True(crypto.ExportPrivateKeyPkcs8(key, out der, out error), error);
        Assert.True(crypto.ImportPrivateKeyPkcs8(der, out imported, out error), error);
        Assert.Equal(key.AlgorithmOid, imported.AlgorithmOid);
        Assert.True(crypto.ExportPrivateKeyPkcs8(imported, out der2, out error), error);
        Assert.Equal(der, der2);
    }
}
