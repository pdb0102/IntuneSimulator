using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ScepWright.Crypto.BouncyCastle;

internal static class BcSelfSigned {
    public static X509Certificate ForKey(BcKey key, string subject_dn) {
        X509V3CertificateGenerator cg;
        X509Name name;
        string sig_alg;

        name = new X509Name(subject_dn);
        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(1));
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        cg.SetNotAfter(DateTime.UtcNow.AddDays(1));
        cg.SetPublicKey(key.KeyPair.Public);
        // Sign with the key's own algorithm: RSA classically, ECDSA for EC (curve-matched digest),
        // ML-DSA/SLH-DSA by OID (BC 2.6.1).
        sig_alg = BcPqKeys.IsPq(key) ? key.AlgorithmOid
                : key.AlgorithmOid == BcAlgorithms.EcPublicKey ? BcAlgorithms.EcdsaSignatureName(key.SizeBits)
                : "SHA256WITHRSA";
        return cg.Generate(new Asn1SignatureFactory(sig_alg, key.KeyPair.Private));
    }
}
