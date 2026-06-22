using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using Xunit;

namespace ScepWright.Tests;

public class EcKeyTests {
    [Theory]
    [InlineData("ec:p256", 256, "p256")]
    [InlineData("ec:p384", 384, "p384")]
    [InlineData("ec:p521", 521, "p521")]
    public void Parses_ec_curves(string text, int size, string param) {
        KeySpec spec;
        string error;

        Assert.True(KeySpec.Parse(text, out spec, out error));
        Assert.Equal("EC", spec.Algorithm);
        Assert.Equal(size, spec.Size);
        Assert.Equal(param, spec.Parameter);
    }

    [Theory]
    [InlineData("ec:p256")]
    [InlineData("ec:p384")]
    [InlineData("ec:p521")]
    public void Generates_ec_keys(string text) {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        string parse_error;
        IScepKey key;
        string key_error;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse(text, out spec, out parse_error));
        Assert.True(crypto.GenerateKey(spec, out key, out key_error), key_error);
        Assert.NotNull(key);
    }

    [Fact]
    public void Ec_public_key_uses_named_curve_not_explicit_params() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo spki;
        Org.BouncyCastle.Asn1.Asn1Encodable parameters;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("ec:p256", out spec, out _);
        Assert.True(crypto.GenerateKey(spec, out key, out _));

        spki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(((BcKey)key).KeyPair.Public);
        parameters = spki.Algorithm.Parameters;

        // Named curve => the AlgorithmIdentifier parameters is the curve OID (P-256 = 1.2.840.10045.3.1.7).
        // Explicit params would be a SEQUENCE — which OpenSSL/TLS stacks reject.
        Assert.IsType<Org.BouncyCastle.Asn1.DerObjectIdentifier>(parameters.ToAsn1Object());
        Assert.Equal("1.2.840.10045.3.1.7", ((Org.BouncyCastle.Asn1.DerObjectIdentifier)parameters.ToAsn1Object()).Id);
    }

    [Fact]
    public void Advertises_ec_signer_capability() {
        BouncyCastleScepCrypto crypto;

        crypto = new BouncyCastleScepCrypto();
        Assert.Contains("1.2.840.10045.2.1", crypto.Capabilities.Signatures);
        Assert.Contains("1.2.840.10045.2.1", crypto.Capabilities.AsymmetricKeys);
    }
}
