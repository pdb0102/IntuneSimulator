using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using ScepWright.Core;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Crypto;
using ScepWright.Tests.Fakes;
using Xunit;

namespace ScepWright.Tests;

// The provider builds the EnvelopedData via BcEnvelope, branching by the recipient cert's algorithm.
// RSA key-transport is exercised end-to-end elsewhere; here we assert the unsupported recipient kinds
// fail cleanly (no throw) with a recognizable message that Core can turn into a finding.
public sealed class RecipientEnvelopeTests {
    // ML-KEM recipients now envelope via the hand-rolled RFC 9629 KEMRecipientInfo (BC 2.6.1 has the
    // KEM primitives but no CMS recipient generator). The request encodes to a non-empty CMS.
    [Fact]
    public void Mlkem_recipient_envelopes() {
        BouncyCastleScepCrypto crypto;
        X509Certificate2 recipient;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        byte[] der;

        crypto = new BouncyCastleScepCrypto();
        recipient = TestCertFactory.Make("ml-kem", KeyUsage.KeyEncipherment);
        builder = ScepRequestBuilder.For(crypto)
            .CaCertificate(recipient)
            .MessageType(ScepWright.Crypto.MessageType.PkcsReq)
            .Subject("CN=recip-test")
            .KeySpec("rsa:2048");
        Assert.True(builder.Build(out message, out subject_key, out error), error);

        Assert.True(message.Encode(crypto, out der, out error), error);
        Assert.True(der.Length > 0);
    }

    [Fact]
    public void Rsa_recipient_still_envelopes() {
        BouncyCastleScepCrypto crypto;
        X509Certificate2 recipient;
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey subject_key;
        string error;
        byte[] der;

        crypto = new BouncyCastleScepCrypto();
        recipient = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment);
        builder = ScepRequestBuilder.For(crypto)
            .CaCertificate(recipient)
            .MessageType(ScepWright.Crypto.MessageType.PkcsReq)
            .Subject("CN=recip-test")
            .KeySpec("rsa:2048");
        Assert.True(builder.Build(out message, out subject_key, out error), error);

        Assert.True(message.Encode(crypto, out der, out error), error);
        Assert.True(der.Length > 0);
    }
}
