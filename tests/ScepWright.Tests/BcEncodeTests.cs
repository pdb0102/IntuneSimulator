using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public class BcEncodeTests {
    private const string MessageTypeOid = "2.16.840.1.113733.1.9.2";

    [Fact]
    public void Encodes_pkcsreq_signeddata_over_envelopeddata() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute msg_type;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=poodle", out _);

        pki = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        msg_type = signer.SignedAttributes[new DerObjectIdentifier(MessageTypeOid)];
        Assert.Equal("19", ((DerPrintableString)msg_type.AttrValues[0]).GetString());
        Assert.Equal(CmsObjectIdentifiers.EnvelopedData.Id, signed.SignedContentType.Id);
    }

    [Fact]
    public void Encode_writes_back_the_sender_nonce_it_used() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute nonce_attr;
        byte[] on_the_wire;

        const string SenderNonceOid = "2.16.840.1.113733.1.9.5";

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=nonce-roundtrip", out _);

        pki = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        // The caller can now see which senderNonce was sent: Encode writes it back onto the object.
        Assert.NotNull(pki.SenderNonce);
        Assert.Equal(16, pki.SenderNonce!.Length);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        nonce_attr = signer.SignedAttributes[new DerObjectIdentifier(SenderNonceOid)];
        on_the_wire = ((Asn1OctetString)nonce_attr.AttrValues[0]).GetOctets();
        Assert.Equal(pki.SenderNonce, on_the_wire);
    }

    [Fact]
    public void Encode_honors_a_preset_sender_nonce() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        byte[] preset;
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute nonce_attr;
        byte[] on_the_wire;

        const string SenderNonceOid = "2.16.840.1.113733.1.9.5";

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=preset-nonce", out _);

        preset = new byte[16];
        for (int i = 0; i < preset.Length; i++) { preset[i] = (byte)(i + 1); }

        pki = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
            SenderNonce = preset,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        nonce_attr = signer.SignedAttributes[new DerObjectIdentifier(SenderNonceOid)];
        on_the_wire = ((Asn1OctetString)nonce_attr.AttrValues[0]).GetOctets();
        Assert.Equal(preset, on_the_wire);
    }

    [Fact]
    public void Encodes_pkcsreq_honors_digest_algorithm_oid() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        PkiMessage pki;
        byte[] der;
        string error;
        CmsSignedData signed;
        SignerInformation signer;
        string expected_oid;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=digest-test", out _);

        expected_oid = Algorithms.OidFor("SHA-512")!;
        pki = new PkiMessage {
            MessageType = MessageType.PkcsReq,
            InnerCsr = csr,
            SignerKey = key,
            RecipientCaCert = ca.CertificateBcl,
            DigestAlgorithmOid = expected_oid,
        };

        Assert.True(crypto.EncodePkiMessage(pki, faults: null, out der, out error), error);

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        Assert.Equal(expected_oid, signer.DigestAlgorithmID.Algorithm.Id);
    }
}
