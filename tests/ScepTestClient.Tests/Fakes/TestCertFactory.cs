using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ScepTestClient.Tests.Fakes;

// Mints X.509 certificates of a chosen algorithm with chosen KeyUsage bits, for recipient-selection
// tests and the fake server's per-profile GetCACert bundles. BC-direct (independent of our provider).
// algorithm: "rsa" | "ec" | "ml-dsa" | "ml-kem". KeyUsage bits use Org.BouncyCastle.Asn1.X509.KeyUsage.
internal static class TestCertFactory {
    public static X509Certificate2 Make(string algorithm, int bc_key_usage) {
        AsymmetricCipherKeyPair pair;
        string sig_alg;
        ISignatureFactory signer;

        pair = GenerateKeyPair(algorithm, out sig_alg);

        // ML-KEM cannot self-sign (it is a KEM, not a signature scheme); issue from a throwaway RSA CA.
        if (algorithm.Equals("ml-kem", StringComparison.OrdinalIgnoreCase)) {
            AsymmetricCipherKeyPair ca_pair;
            string ca_sig;

            ca_pair = GenerateKeyPair("rsa", out ca_sig);
            signer = new Asn1SignatureFactory("SHA256WITHRSA", ca_pair.Private);
            return Build(pair.Public, signer, "CN=test-ca", "CN=test-kem", bc_key_usage);
        }

        signer = new Asn1SignatureFactory(sig_alg, pair.Private);
        return Build(pair.Public, signer, "CN=test", "CN=test", bc_key_usage);
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm, out string sig_alg) {
        SecureRandom random;

        random = new SecureRandom();
        switch (algorithm.ToLowerInvariant()) {
            case "rsa": {
                RsaKeyPairGenerator rsa_gen;

                rsa_gen = new RsaKeyPairGenerator();
                rsa_gen.Init(new KeyGenerationParameters(random, 2048));
                sig_alg = "SHA256WITHRSA";
                return rsa_gen.GenerateKeyPair();
            }
            case "ec": {
                ECKeyPairGenerator ec_gen;

                ec_gen = new ECKeyPairGenerator();
                ec_gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));
                sig_alg = "SHA256WITHECDSA";
                return ec_gen.GenerateKeyPair();
            }
            case "ml-dsa": {
                MLDsaKeyPairGenerator mldsa_gen;

                mldsa_gen = new MLDsaKeyPairGenerator();
                mldsa_gen.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
                sig_alg = "2.16.840.1.101.3.4.3.18";
                return mldsa_gen.GenerateKeyPair();
            }
            case "ml-kem": {
                MLKemKeyPairGenerator mlkem_gen;

                mlkem_gen = new MLKemKeyPairGenerator();
                mlkem_gen.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
                sig_alg = string.Empty;
                return mlkem_gen.GenerateKeyPair();
            }
            default:
                throw new ArgumentException($"unsupported test cert algorithm '{algorithm}'");
        }
    }

    private static X509Certificate2 Build(AsymmetricKeyParameter subject_public, ISignatureFactory signer, string issuer_dn, string subject_dn, int bc_key_usage) {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(System.DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(new X509Name(issuer_dn));
        cg.SetSubjectDN(new X509Name(subject_dn));
        cg.SetNotBefore(System.DateTime.UtcNow.AddMinutes(-5));
        cg.SetNotAfter(System.DateTime.UtcNow.AddYears(1));
        cg.SetPublicKey(subject_public);
        if (bc_key_usage != 0) {
            cg.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(bc_key_usage));
        }
        return new X509Certificate2(cg.Generate(signer).GetEncoded());
    }
}
