using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScepTestClient.Crypto.BouncyCastle;
using Xunit;

namespace ScepTestClient.Tests;

// Direct round-trip of the hand-rolled RFC 9629 ML-KEM CMS envelope, for both the SCEP-used CBC
// (EnvelopedData) path and the ported GCM (AuthEnvelopedData) path.
public sealed class KemEnvelopeTests {
    private const string Aes128CbcOid = "2.16.840.1.101.3.4.1.2";

    [Theory]
    [InlineData(false)]   // AES-128-CBC EnvelopedData (SCEP)
    [InlineData(true)]    // AES-256-GCM AuthEnvelopedData (ported, not used by SCEP)
    public void Kem_envelope_roundtrips(bool gcm) {
        MLKemKeyPairGenerator generator;
        AsymmetricCipherKeyPair pair;
        MLKemPublicKeyParameters pub;
        MLKemPrivateKeyParameters priv;
        byte[] plaintext;
        byte[] key_id;
        byte[] der;
        byte[] recovered;

        generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MLKemParameters.ml_kem_768));
        pair = generator.GenerateKeyPair();
        pub = (MLKemPublicKeyParameters)pair.Public;
        priv = (MLKemPrivateKeyParameters)pair.Private;

        plaintext = Encoding.UTF8.GetBytes("the quick brown fox jumps over the lazy SCEP request");
        key_id = new byte[20];

        der = gcm
            ? BcKemEnvelope.EncryptGcm(plaintext, pub, key_id)
            : BcKemEnvelope.EncryptCbc(plaintext, pub, key_id, Aes128CbcOid);

        recovered = BcKemEnvelope.Decrypt(der, priv);
        Assert.Equal(plaintext, recovered);
    }

    // EnvelopedData with an ori (OtherRecipientInfo) recipient MUST be version 3 (RFC 5652 §6.1).
    [Fact]
    public void Cbc_envelope_is_version_3() {
        MLKemKeyPairGenerator generator;
        AsymmetricCipherKeyPair pair;
        MLKemPublicKeyParameters pub;
        byte[] der;
        ContentInfo ci;
        EnvelopedData ed;

        generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MLKemParameters.ml_kem_768));
        pair = generator.GenerateKeyPair();
        pub = (MLKemPublicKeyParameters)pair.Public;

        der = BcKemEnvelope.EncryptCbc(Encoding.UTF8.GetBytes("v3"), pub, new byte[20], Aes128CbcOid);
        ci = ContentInfo.GetInstance(Asn1Object.FromByteArray(der));
        ed = EnvelopedData.GetInstance(ci.Content);
        Assert.Equal(3, ed.Version.IntValueExact);
    }
}
