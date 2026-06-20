using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;

namespace ScepTestClient.Crypto.BouncyCastle;

// Builds the SCEP inner CMS EnvelopedData, choosing the RecipientInfo by the recipient certificate's
// key algorithm. This is the single place recipient-algorithm branching lives in the provider; an
// intermediate ASN.1 layer (design spec §3.5) could later own this, but for now it stays internal.
internal static class BcEnvelope {
    private const string OidRsa = "1.2.840.113549.1.1.1";
    private const string OidEc = "1.2.840.10045.2.1";
    private const string OidMlKemArc = "2.16.840.1.101.3.4.4.";

    public static byte[] Build(X509Certificate2 recipient_cert, byte[] content_der, string content_encryption_oid, SecureRandom random) {
        string algorithm_oid;
        Org.BouncyCastle.X509.X509Certificate bc_cert;
        CmsEnvelopedDataGenerator generator;
        CmsEnvelopedData enveloped;

        algorithm_oid = recipient_cert.GetKeyAlgorithm();
        generator = new CmsEnvelopedDataGenerator(random);

        if (algorithm_oid == OidRsa) {
            bc_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(recipient_cert.RawData);
            generator.AddKeyTransRecipient(bc_cert);
        } else if (algorithm_oid == OidEc) {
            // EC key-agreement (KeyAgreeRecipientInfo / ephemeral-static ECDH) is a clean drop-in here
            // — provider-internal, no contract change — but not implemented yet.
            throw new NotSupportedException("EC key-agreement recipients are not implemented by this provider");
        } else if (algorithm_oid.StartsWith(OidMlKemArc, StringComparison.Ordinal)) {
            // ML-KEM (RFC 9629 KEMRecipientInfo) — BouncyCastle 2.5.0 has no CMS KEM recipient generator;
            // would be a hand-rolled drop-in here, or supplied by an external provider.
            throw new NotSupportedException("ML-KEM (KEMRecipientInfo) recipients are not implemented by this provider");
        } else {
            throw new NotSupportedException($"recipient key algorithm '{algorithm_oid}' cannot be used to encrypt a SCEP request");
        }

        enveloped = generator.Generate(new CmsProcessableByteArray(content_der), content_encryption_oid);
        return enveloped.GetEncoded();
    }
}
