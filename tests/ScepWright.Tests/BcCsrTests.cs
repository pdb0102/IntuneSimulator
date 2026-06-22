using Org.BouncyCastle.Pkcs;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using Xunit;

namespace ScepWright.Tests;

public class BcCsrTests {
    [Fact]
    public void Builds_signed_csr_with_subject_and_challenge() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key, ChallengePassword = "s3cret", Sid = "S-1-5-21-1-2-3-1000" };
        Assert.True(csr.SetSubject("CN=poodle", out _));

        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        Assert.Contains("poodle", parsed.GetCertificationRequestInfo().Subject.ToString());
    }

    // A requested EKU must be emitted as an ExtendedKeyUsage extension in the CSR's extensionRequest
    // attribute, supporting both common names (serverAuth) and raw OIDs.
    [Fact]
    public void Builds_csr_with_requested_extended_key_usage() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;
        Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo info;
        Org.BouncyCastle.Asn1.X509.X509Extensions extensions;
        Org.BouncyCastle.Asn1.X509.X509Extension eku_ext;
        Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage eku;

        crypto = new BouncyCastleScepCrypto();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);

        csr = new Pkcs10 { Key = key };
        csr.Ekus.Add("serverAuth");
        csr.Ekus.Add("1.3.6.1.5.5.7.3.2");   // raw OID for clientAuth
        Assert.True(csr.SetSubject("CN=poodle", out _));

        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());

        info = parsed.GetCertificationRequestInfo();
        extensions = ExtensionsFrom(info);
        Assert.NotNull(extensions);
        eku_ext = extensions.GetExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.ExtendedKeyUsage);
        Assert.NotNull(eku_ext);

        eku = Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage.GetInstance(eku_ext.GetParsedValue());
        Assert.True(eku.HasKeyPurposeId(Org.BouncyCastle.Asn1.X509.KeyPurposeID.id_kp_serverAuth));
        Assert.True(eku.HasKeyPurposeId(Org.BouncyCastle.Asn1.X509.KeyPurposeID.id_kp_clientAuth));
    }

    private static Org.BouncyCastle.Asn1.X509.X509Extensions ExtensionsFrom(Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo info) {
        Org.BouncyCastle.Asn1.Asn1Set attributes;

        attributes = info.Attributes;
        foreach (Org.BouncyCastle.Asn1.Asn1Encodable encodable in attributes) {
            Org.BouncyCastle.Asn1.Pkcs.AttributePkcs attr;

            attr = Org.BouncyCastle.Asn1.Pkcs.AttributePkcs.GetInstance(encodable);
            if (attr.AttrType.Equals(Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtExtensionRequest)) {
                return Org.BouncyCastle.Asn1.X509.X509Extensions.GetInstance(attr.AttrValues[0]);
            }
        }
        return null!;
    }
}
