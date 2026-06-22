using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace ScepWright.Server;

/// <summary>
/// A self-contained, UNTRUSTED test certificate authority for the built-in SCEP server. Generates its
/// own signing (and optional separate RA encryption) certificate, persists/loads its keys, and handles
/// the SCEP PKIOperation, GetCert, GetCRL and CertPoll message flows.
/// </summary>
public sealed class ScepCa {
    /// <summary>Gets the CA signing key pair.</summary>
    public AsymmetricCipherKeyPair KeyPair { get; }
    /// <summary>Gets the CA signing certificate (BouncyCastle form).</summary>
    public Org.BouncyCastle.X509.X509Certificate Certificate { get; }
    /// <summary>Gets the CA signing certificate (.NET form).</summary>
    public X509Certificate2 CertificateBcl { get; }

    private readonly Dictionary<string, Org.BouncyCastle.X509.X509Certificate> _issued_by_serial = new Dictionary<string, Org.BouncyCastle.X509.X509Certificate>();

    /// <summary>Gets or sets whether enrollment requests are held PENDING (CertRep with pkiStatus PENDING) rather than issued immediately.</summary>
    public bool PendingMode { get; set; }
    /// <summary>Gets or sets the challenge password the CA requires on enrollment, or <c>null</c> to accept any.</summary>
    public string? ExpectedChallenge { get; set; }

    /// <summary>
    /// Gets or sets whether NDES emulation is active. When set, enrollment requires a one-time challenge
    /// password that this CA itself issued via <see cref="IssueNdesChallenge"/> (and consumes on use).
    /// </summary>
    public bool NdesMode { get; set; }
    private readonly HashSet<string> _ndes_challenges = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Issues a fresh one-time NDES challenge password and records it as valid for one enrollment.</summary>
    /// <returns>The newly issued challenge password.</returns>
    public string IssueNdesChallenge() {
        byte[] bytes;
        string challenge;

        bytes = new byte[16];
        new SecureRandom().NextBytes(bytes);
        challenge = Convert.ToHexString(bytes);
        lock (_ndes_challenges) { _ndes_challenges.Add(challenge); }
        return challenge;
    }

    /// <summary>
    /// Gets the optional separate RA encryption certificate (SCEP split signing vs. encryption certs).
    /// When set, GetCACert presents a [signing, encryption] bundle and requests are decrypted with its key.
    /// </summary>
    public X509Certificate2? EncryptionCert { get; private set; }
    private AsymmetricCipherKeyPair? _encryption_key;
    private AsymmetricKeyParameter RecipientKey => _encryption_key?.Private ?? KeyPair.Private;
    private string _ca_signature_algorithm = "SHA256WITHRSA";

    private ScepCa(AsymmetricCipherKeyPair keyPair, Org.BouncyCastle.X509.X509Certificate cert) {
        KeyPair = keyPair;
        Certificate = cert;
        CertificateBcl = new X509Certificate2(cert.GetEncoded());
    }

    /// <summary>Persists the CA certificate and keys to the directory with plaintext keys.</summary>
    /// <param name="directory">The directory to write the CA material into.</param>
    public void Persist(string directory) {
        Persist(directory, null);
    }

    /// <summary>Persists the CA certificate and keys to the directory.</summary>
    /// <param name="directory">The directory to write the CA material into.</param>
    /// <param name="passphrase">When non-empty, the private keys are written as encrypted PKCS#8 (PBES2) and the plaintext key files are not written; otherwise the plaintext layout is used.</param>
    public void Persist(string directory, string? passphrase) {
        bool encrypt;

        encrypt = !string.IsNullOrEmpty(passphrase);

        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "ca.cert.der"), Certificate.GetEncoded());
        WriteKey(directory, "ca.key.pkcs8", KeyPair.Private, encrypt, passphrase);
        File.WriteAllText(Path.Combine(directory, "sigalg.txt"), _ca_signature_algorithm);

        if (EncryptionCert != null && _encryption_key != null) {
            File.WriteAllBytes(Path.Combine(directory, "ra.cert.der"), EncryptionCert.RawData);
            WriteKey(directory, "ra.key.pkcs8", _encryption_key.Private, encrypt, passphrase);
        }
    }

    private static void WriteKey(string directory, string base_name, AsymmetricKeyParameter private_key, bool encrypt, string? passphrase) {
        if (encrypt) {
            File.WriteAllBytes(Path.Combine(directory, base_name + ".enc"), CaKeyProtection.Encrypt(private_key, passphrase!));
        } else {
            File.WriteAllBytes(Path.Combine(directory, base_name), PrivateKeyInfoFactory.CreatePrivateKeyInfo(private_key).GetDerEncoded());
        }
    }

    /// <summary>Loads a previously persisted CA from the directory, expecting plaintext keys.</summary>
    /// <param name="directory">The directory holding the persisted CA material.</param>
    public static ScepCa LoadFrom(string directory) {
        return LoadFrom(directory, null);
    }

    /// <summary>
    /// Loads a previously persisted CA from the directory, auto-detecting an encrypted (<c>*.pkcs8.enc</c>)
    /// or plaintext (<c>*.pkcs8</c>) key.
    /// </summary>
    /// <param name="directory">The directory holding the persisted CA material.</param>
    /// <param name="passphrase">The passphrase for an encrypted key, or <c>null</c> for a plaintext key.</param>
    /// <exception cref="CaKeyProtectionException">The key is encrypted and the passphrase is wrong or missing.</exception>
    public static ScepCa LoadFrom(string directory, string? passphrase) {
        Org.BouncyCastle.X509.X509Certificate ca_cert;
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter ca_private;
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ca_pair;
        ScepCa self;
        string ra_cert_path;

        ca_cert = new Org.BouncyCastle.X509.X509CertificateParser()
            .ReadCertificate(File.ReadAllBytes(Path.Combine(directory, "ca.cert.der")));
        ca_private = ReadKey(directory, "ca.key.pkcs8", passphrase);
        ca_pair = new Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair(ca_cert.GetPublicKey(), ca_private);

        self = new ScepCa(ca_pair, ca_cert);
        self._ca_signature_algorithm = File.ReadAllText(Path.Combine(directory, "sigalg.txt"));

        ra_cert_path = Path.Combine(directory, "ra.cert.der");
        if (File.Exists(ra_cert_path)) {
            Org.BouncyCastle.X509.X509Certificate ra_cert;
            Org.BouncyCastle.Crypto.AsymmetricKeyParameter ra_private;

            ra_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(File.ReadAllBytes(ra_cert_path));
            ra_private = ReadKey(directory, "ra.key.pkcs8", passphrase);
            self.EncryptionCert = new X509Certificate2(ra_cert.GetEncoded());
            self._encryption_key = new Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair(ra_cert.GetPublicKey(), ra_private);
        }

        return self;
    }

    private static AsymmetricKeyParameter ReadKey(string directory, string base_name, string? passphrase) {
        string enc_path;
        string plain_path;

        enc_path = Path.Combine(directory, base_name + ".enc");
        plain_path = Path.Combine(directory, base_name);
        if (File.Exists(enc_path)) {
            return CaKeyProtection.Decrypt(File.ReadAllBytes(enc_path), passphrase);
        }
        return Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(File.ReadAllBytes(plain_path));
    }

    /// <summary>Creates a default CA: a single dual-use 2048-bit RSA certificate that both signs and acts as the envelope recipient.</summary>
    public static ScepCa Create() {
        RsaKeyPairGenerator gen;
        AsymmetricCipherKeyPair pair;
        X509V3CertificateGenerator cg;
        X509Name name;

        gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        pair = gen.GenerateKeyPair();

        name = new X509Name("CN=Test SCEP CA");
        cg = new X509V3CertificateGenerator();
        // Fixed serial (CA=1, RA=2) by design: this is a throwaway UNTRUSTED test CA, so cross-profile
        // serial uniqueness is a non-goal. Issued LEAF certs get distinct time-based serials.
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        cg.SetPublicKey(pair.Public);
        // Default profile is a single dual-use RSA cert: it is also the envelope recipient, so it
        // carries keyEncipherment alongside keyCertSign.
        AddCaExtensions(cg, pair.Public, KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.KeyCertSign);

        return new ScepCa(pair, cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", pair.Private)));
    }

    /// <summary>
    /// Creates a CA whose single dual-use signing certificate uses the chosen algorithm. RSA carries
    /// keyEncipherment and EC carries keyAgreement (so the cert is also the envelope recipient); ML-DSA is
    /// signature-only and cannot be an encryption recipient.
    /// </summary>
    /// <param name="ca_algo">The CA signing algorithm: <c>rsa</c>, <c>ec</c> or <c>ml-dsa</c>.</param>
    /// <param name="label">The CA subject common name, or <c>null</c> for a default.</param>
    public static ScepCa Create(string ca_algo, string? label = null) {
        AsymmetricCipherKeyPair pair;
        string sig_alg;
        int key_usage;
        X509Name name;
        X509V3CertificateGenerator cg;
        ScepCa ca;

        pair = GenerateCaKeyPair(ca_algo, out sig_alg);
        key_usage = ca_algo.ToLowerInvariant() switch {
            "ec" => KeyUsage.DigitalSignature | KeyUsage.KeyAgreement | KeyUsage.KeyCertSign,
            "rsa" => KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.KeyCertSign,
            _ => KeyUsage.DigitalSignature | KeyUsage.KeyCertSign,
        };
        // A distinct subject per profile (label) so subject-keyed trust stores don't collapse every
        // profile's CA onto one DN. Default keeps the historical "CN=Test SCEP CA".
        name = new X509Name("CN=" + (label ?? "Test SCEP CA"));
        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        cg.SetPublicKey(pair.Public);
        AddCaExtensions(cg, pair.Public, key_usage);
        ca = new ScepCa(pair, cg.Generate(new Asn1SignatureFactory(sig_alg, pair.Private)));
        ca._ca_signature_algorithm = sig_alg;
        return ca;
    }

    // Generates the CA signing keypair for the chosen algorithm and reports the X.509 signature
    // algorithm name/OID to use for issuing and CRLs.
    private static AsymmetricCipherKeyPair GenerateCaKeyPair(string ca_algo, out string sig_alg) {
        SecureRandom random;

        random = new SecureRandom();
        switch (ca_algo.ToLowerInvariant()) {
            case "rsa": {
                RsaKeyPairGenerator rsa_gen;

                rsa_gen = new RsaKeyPairGenerator();
                rsa_gen.Init(new KeyGenerationParameters(random, 2048));
                sig_alg = "SHA256WITHRSA";
                return rsa_gen.GenerateKeyPair();
            }
            case "ec": {
                Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator ec_gen;

                ec_gen = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator("ECDSA");
                ec_gen.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, random));
                sig_alg = "SHA256WITHECDSA";
                return ec_gen.GenerateKeyPair();
            }
            case "ml-dsa": {
                Org.BouncyCastle.Crypto.Generators.MLDsaKeyPairGenerator mldsa_gen;

                mldsa_gen = new Org.BouncyCastle.Crypto.Generators.MLDsaKeyPairGenerator();
                mldsa_gen.Init(new Org.BouncyCastle.Crypto.Parameters.MLDsaKeyGenerationParameters(random, Org.BouncyCastle.Crypto.Parameters.MLDsaParameters.ml_dsa_65));
                sig_alg = "2.16.840.1.101.3.4.3.18";
                return mldsa_gen.GenerateKeyPair();
            }
            case "slh-dsa": {
                Org.BouncyCastle.Crypto.Generators.SlhDsaKeyPairGenerator slhdsa_gen;

                slhdsa_gen = new Org.BouncyCastle.Crypto.Generators.SlhDsaKeyPairGenerator();
                slhdsa_gen.Init(new Org.BouncyCastle.Crypto.Parameters.SlhDsaKeyGenerationParameters(random, Org.BouncyCastle.Crypto.Parameters.SlhDsaParameters.slh_dsa_sha2_128f));
                sig_alg = "2.16.840.1.101.3.4.3.21";   // SLH-DSA-SHA2-128f
                return slhdsa_gen.GenerateKeyPair();
            }
            default:
                throw new ArgumentException($"unsupported CA algorithm '{ca_algo}'");
        }
    }

    /// <summary>
    /// Creates a CA with a SEPARATE RA encryption certificate: the signing cert carries
    /// digitalSignature+keyCertSign (no keyEncipherment) and the RA cert carries the encryption usage.
    /// GetCACert presents both, and requests must be enveloped to the RA cert.
    /// </summary>
    /// <param name="enc_algo">The RA encryption algorithm: <c>rsa</c>, <c>ec</c> or <c>ml-kem</c>.</param>
    /// <param name="ca_algo">The CA signing algorithm: <c>rsa</c>, <c>ec</c>, <c>ml-dsa</c> or <c>slh-dsa</c>.</param>
    /// <param name="label">The CA subject common name, or <c>null</c> for a default.</param>
    public static ScepCa CreateWithRaEncryption(string enc_algo = "rsa", string ca_algo = "rsa", string? label = null) {
        AsymmetricCipherKeyPair ca_pair;
        string ca_sig_alg;
        X509Name ca_name;
        X509V3CertificateGenerator ca_cg;
        ScepCa ca;
        AsymmetricCipherKeyPair ra_pair;
        int ra_key_usage;
        X509V3CertificateGenerator ra_cg;

        ca_pair = GenerateCaKeyPair(ca_algo, out ca_sig_alg);
        ca_name = new X509Name("CN=" + (label ?? "Test SCEP CA (split)"));
        ca_cg = new X509V3CertificateGenerator();
        ca_cg.SetSerialNumber(BigInteger.One);
        ca_cg.SetIssuerDN(ca_name);
        ca_cg.SetSubjectDN(ca_name);
        ca_cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        ca_cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        ca_cg.SetPublicKey(ca_pair.Public);
        AddCaExtensions(ca_cg, ca_pair.Public, KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
        ca = new ScepCa(ca_pair, ca_cg.Generate(new Asn1SignatureFactory(ca_sig_alg, ca_pair.Private)));
        ca._ca_signature_algorithm = ca_sig_alg;

        ra_pair = GenerateRaKeyPair(enc_algo, out ra_key_usage);
        ra_cg = new X509V3CertificateGenerator();
        ra_cg.SetSerialNumber(BigInteger.ValueOf(2));
        ra_cg.SetIssuerDN(ca_name);
        ra_cg.SetSubjectDN(new X509Name("CN=Test RA Encryption" + (label != null ? " (" + label + ")" : string.Empty)));
        ra_cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        ra_cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        ra_cg.SetPublicKey(ra_pair.Public);
        // RA encryption cert is an end-entity (not a CA): CA:FALSE + its encipherment/agreement usage + SKI.
        ra_cg.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        ra_cg.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(ra_key_usage));
        ra_cg.AddExtension(X509Extensions.SubjectKeyIdentifier, false, Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.CreateSubjectKeyIdentifier(ra_pair.Public));

        ca._encryption_key = ra_pair;
        ca.EncryptionCert = new X509Certificate2(ra_cg.Generate(new Asn1SignatureFactory(ca_sig_alg, ca_pair.Private)).GetEncoded());
        return ca;
    }

    // Generates the RA encryption keypair for the chosen algorithm and reports the matching KeyUsage:
    // RSA/ML-KEM -> keyEncipherment, EC -> keyAgreement.
    private static AsymmetricCipherKeyPair GenerateRaKeyPair(string enc_algo, out int key_usage) {
        SecureRandom random;

        random = new SecureRandom();
        switch (enc_algo.ToLowerInvariant()) {
            case "rsa": {
                RsaKeyPairGenerator rsa_gen;

                rsa_gen = new RsaKeyPairGenerator();
                rsa_gen.Init(new KeyGenerationParameters(random, 2048));
                key_usage = KeyUsage.KeyEncipherment;
                return rsa_gen.GenerateKeyPair();
            }
            case "ec": {
                Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator ec_gen;

                ec_gen = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator("ECDH");
                ec_gen.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, random));
                key_usage = KeyUsage.KeyAgreement;
                return ec_gen.GenerateKeyPair();
            }
            case "ml-kem": {
                Org.BouncyCastle.Crypto.Generators.MLKemKeyPairGenerator mlkem_gen;

                mlkem_gen = new Org.BouncyCastle.Crypto.Generators.MLKemKeyPairGenerator();
                mlkem_gen.Init(new Org.BouncyCastle.Crypto.Parameters.MLKemKeyGenerationParameters(random, Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768));
                key_usage = KeyUsage.KeyEncipherment;
                return mlkem_gen.GenerateKeyPair();
            }
            default:
                throw new ArgumentException($"unsupported RA encryption algorithm '{enc_algo}'");
        }
    }

    /// <summary>
    /// Creates a CA with a single signature-only certificate (digitalSignature+keyCertSign, no
    /// keyEncipherment) — models a server that cannot receive an encrypted SCEP request.
    /// </summary>
    /// <param name="label">The CA subject common name, or <c>null</c> for a default.</param>
    public static ScepCa CreateSigningOnly(string? label = null) {
        RsaKeyPairGenerator gen;
        AsymmetricCipherKeyPair pair;
        X509Name name;
        X509V3CertificateGenerator cg;

        gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        pair = gen.GenerateKeyPair();
        name = new X509Name("CN=" + (label ?? "Test SCEP CA (signing only)"));
        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(name);
        cg.SetSubjectDN(name);
        cg.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(5));
        cg.SetPublicKey(pair.Public);
        AddCaExtensions(cg, pair.Public, KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
        return new ScepCa(pair, cg.Generate(new Asn1SignatureFactory("SHA256WITHRSA", pair.Private)));
    }

    // GetCACert response: a single cert by default, or a degenerate PKCS#7 [signing, encryption]
    // bundle when a separate RA encryption cert is configured.
    /// <summary>Builds the GetCACert response body: the bare signing certificate, or a degenerate CMS [signing, encryption] bundle when a separate RA cert is present.</summary>
    public byte[] BuildCaCertBundleDer() {
        Org.BouncyCastle.X509.X509Certificate enc_bc;
        IStore<Org.BouncyCastle.X509.X509Certificate> store;
        CmsSignedDataGenerator gen;

        if (EncryptionCert is null) {
            return Certificate.GetEncoded();
        }

        enc_bc = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(EncryptionCert.RawData);
        store = CollectionUtilities.CreateStore(new[] { Certificate, enc_bc });
        gen = new CmsSignedDataGenerator();
        gen.AddCertificates(store);
        return gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
    }

    // Builds a CMS SignerInfoGenerator for the CA key via the SignerInfoGeneratorBuilder path, which
    // in BC 2.6.1 supports RSA, ECDSA, and ML-DSA/SLH-DSA signing keys uniformly (the legacy AddSigner
    // overloads cannot sign with PQ keys). The base table carries the SCEP signed attributes;
    // contentType + messageDigest are added automatically.
    private SignerInfoGenerator BuildCaSigner(Org.BouncyCastle.Asn1.Cms.AttributeTable signed_attrs) {
        return new SignerInfoGeneratorBuilder()
            .WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signed_attrs))
            .Build(new Asn1SignatureFactory(_ca_signature_algorithm, KeyPair.Private), Certificate);
    }

    // CA cert extensions: basicConstraints critical CA:TRUE, keyUsage (always with cRLSign) critical,
    // and a subjectKeyIdentifier — so `openssl verify` accepts chains the CA issues.
    private static void AddCaExtensions(X509V3CertificateGenerator cg, AsymmetricKeyParameter ca_public, int key_usage) {
        cg.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        cg.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(key_usage | KeyUsage.CrlSign));
        cg.AddExtension(X509Extensions.SubjectKeyIdentifier, false, Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.CreateSubjectKeyIdentifier(ca_public));
    }

    // Leaf (issued client) cert extensions: basicConstraints CA:FALSE, keyUsage (RSA adds
    // keyEncipherment), EKU (the CSR's requested ExtendedKeyUsage if any, else clientAuth), plus
    // SKI/AKI for a verifiable chain.
    private void AddLeafExtensions(X509V3CertificateGenerator cg, AsymmetricKeyParameter subject_public_key, Org.BouncyCastle.Asn1.X509.X509Extension? requested_eku) {
        int usage;

        usage = KeyUsage.DigitalSignature;
        if (subject_public_key is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters) {
            usage |= KeyUsage.KeyEncipherment;
        }
        cg.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        cg.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(usage));
        if (requested_eku != null) {
            cg.AddExtension(X509Extensions.ExtendedKeyUsage, requested_eku.IsCritical, requested_eku.GetParsedValue());
        } else {
            cg.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_clientAuth));
        }
        cg.AddExtension(X509Extensions.SubjectKeyIdentifier, false, Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.CreateSubjectKeyIdentifier(subject_public_key));
        cg.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.CreateAuthorityKeyIdentifier(Certificate));
    }

    internal Org.BouncyCastle.X509.X509Certificate Issue(AsymmetricKeyParameter subject_public_key, string subject_dn) {
        return Issue(subject_public_key, subject_dn, requested_san: null, requested_eku: null);
    }

    internal Org.BouncyCastle.X509.X509Certificate Issue(AsymmetricKeyParameter subject_public_key, string subject_dn, Org.BouncyCastle.Asn1.X509.X509Extension? requested_san) {
        return Issue(subject_public_key, subject_dn, requested_san, requested_eku: null);
    }

    internal Org.BouncyCastle.X509.X509Certificate Issue(AsymmetricKeyParameter subject_public_key, string subject_dn, Org.BouncyCastle.Asn1.X509.X509Extension? requested_san, Org.BouncyCastle.Asn1.X509.X509Extension? requested_eku) {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(Certificate.SubjectDN);
        cg.SetSubjectDN(new X509Name(subject_dn));
        cg.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(1));
        cg.SetPublicKey(subject_public_key);
        AddLeafExtensions(cg, subject_public_key, requested_eku);
        // Honor a SubjectAltName the client requested in the CSR (extensionRequest), so the issued leaf
        // actually carries it — a real CA's RA policy would gate this; the test CA mirrors the request.
        if (requested_san != null) {
            cg.AddExtension(X509Extensions.SubjectAlternativeName, requested_san.IsCritical, requested_san.GetParsedValue());
        }

        Org.BouncyCastle.X509.X509Certificate issued;
        issued = cg.Generate(new Asn1SignatureFactory(_ca_signature_algorithm, KeyPair.Private));
        _issued_by_serial[issued.SerialNumber.ToString(16).ToUpperInvariant()] = issued;
        return issued;
    }

    internal Org.BouncyCastle.X509.X509Certificate IssueExpired(AsymmetricKeyParameter subject_public_key, string subject_dn) {
        X509V3CertificateGenerator cg;

        cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks & 0x7fffffff));
        cg.SetIssuerDN(Certificate.SubjectDN);
        cg.SetSubjectDN(new X509Name(subject_dn));
        cg.SetNotBefore(DateTime.UtcNow.AddYears(-2));
        cg.SetNotAfter(DateTime.UtcNow.AddYears(-1));
        cg.SetPublicKey(subject_public_key);
        AddLeafExtensions(cg, subject_public_key, requested_eku: null);
        return cg.Generate(new Asn1SignatureFactory(_ca_signature_algorithm, KeyPair.Private));
    }

    // Builds a SUCCESS CertRep: SignedData (signed by CA) whose content is EnvelopedData (to the recipient cert)
    // of a degenerate PKCS#7 carrying the issued cert. Signed attrs: pkiStatus=0, messageType=3 (CertRep),
    // transId echoed, recipientNonce echoes the request senderNonce (pass any 16 bytes).
    // A SCEP response (success/pending/CRL) is enveloped to the requester's signer certificate. If that
    // key can't receive an envelope (e.g. an ML-DSA / SLH-DSA signature-only renewal cert), the server
    // cannot deliver the response — answer with a clean failInfo (badRequest) instead of throwing into
    // an unhandled 500. The failure CertRep carries no encrypted content, so it is always deliverable.
    private bool CanEnvelopeTo(X509Certificate2 recipient_cert) {
        const string OidRsa = "1.2.840.113549.1.1.1";
        const string OidEc = "1.2.840.10045.2.1";
        string oid;

        oid = recipient_cert.GetKeyAlgorithm();
        return oid == OidRsa || oid == OidEc;
    }

    internal byte[] BuildSuccessCertRep(Org.BouncyCastle.X509.X509Certificate issued_cert, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        IStore<Org.BouncyCastle.X509.X509Certificate> issued_cert_store;
        byte[] degenerate_bytes;

        if (!CanEnvelopeTo(recipient_cert)) {
            return BuildFailureCertRep(recipient_cert, trans_id, recipient_nonce, "2");
        }

        issued_cert_store = CollectionUtilities.CreateStore(new[] { issued_cert });
        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_gen.AddCertificates(issued_cert_store);
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "0");
    }

    // Builds a PENDING CertRep: pkiStatus=3, messageType=3 (CertRep), no issued cert (empty degenerate PKCS#7).
    internal byte[] BuildPendingCertRep(X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;

        if (!CanEnvelopeTo(recipient_cert)) {
            return BuildFailureCertRep(recipient_cert, trans_id, recipient_nonce, "2");
        }

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "3");
    }

    internal Org.BouncyCastle.X509.X509Crl GenerateCrl() {
        X509V2CrlGenerator crl_gen;

        crl_gen = new X509V2CrlGenerator();
        crl_gen.SetIssuerDN(Certificate.SubjectDN);
        crl_gen.SetThisUpdate(DateTime.UtcNow.AddMinutes(-5));
        crl_gen.SetNextUpdate(DateTime.UtcNow.AddDays(7));
        crl_gen.AddCrlEntry(BigInteger.ValueOf(99), DateTime.UtcNow.AddMinutes(-1), Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise);
        return crl_gen.Generate(new Asn1SignatureFactory(_ca_signature_algorithm, KeyPair.Private));
    }

    internal byte[] BuildSuccessCrlRep(Org.BouncyCastle.X509.X509Crl crl, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce) {
        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;

        if (!CanEnvelopeTo(recipient_cert)) {
            return BuildFailureCertRep(recipient_cert, trans_id, recipient_nonce, "2");
        }

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_gen.AddCrl(crl);
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();
        return EnvelopeAndSign(degenerate_bytes, recipient_cert, trans_id, recipient_nonce, "3", "0");
    }

    internal byte[] BuildFailureCertRep(X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce, string fail_info) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
        const string OidFailInfo = "2.16.840.1.113733.1.9.4";
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";

        CmsSignedDataGenerator degenerate_gen;
        byte[] degenerate_bytes;
        Dictionary<DerObjectIdentifier, object> attrs;
        IStore<Org.BouncyCastle.X509.X509Certificate> ca_cert_store;
        CmsSignedDataGenerator signed_gen;
        CmsSignedData signed_data;

        degenerate_gen = new CmsSignedDataGenerator();
        degenerate_bytes = degenerate_gen.Generate(new CmsProcessableByteArray(System.Array.Empty<byte>()), false).GetEncoded();

        attrs = new Dictionary<DerObjectIdentifier, object>();
        attrs[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString("3")));
        attrs[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString("2")));
        attrs[new DerObjectIdentifier(OidFailInfo)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidFailInfo), new DerSet(new DerPrintableString(fail_info)));
        attrs[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString(trans_id)));
        attrs[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(recipient_nonce)));

        ca_cert_store = CollectionUtilities.CreateStore(new[] { Certificate });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signed_gen.AddSignerInfoGenerator(BuildCaSigner(new Org.BouncyCastle.Asn1.Cms.AttributeTable(attrs)));
        signed_gen.AddCertificates(ca_cert_store);
        signed_data = signed_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), true);
        return signed_data.GetEncoded();
    }

    private byte[] EnvelopeAndSign(byte[] degenerate_bytes, X509Certificate2 recipient_cert, string trans_id, byte[] recipient_nonce, string message_type, string pki_status) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        const string OidPkiStatus = "2.16.840.1.113733.1.9.3";
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidRecipientNonce = "2.16.840.1.113733.1.9.6";

        Org.BouncyCastle.X509.X509Certificate recipient_bc_cert;
        CmsEnvelopedDataGenerator enveloped_gen;
        CmsEnvelopedData enveloped;
        byte[] enveloped_bytes;
        Dictionary<DerObjectIdentifier, object> signed_attrs_dict;
        Org.BouncyCastle.Asn1.Cms.AttributeTable signed_attr_table;
        IStore<Org.BouncyCastle.X509.X509Certificate> ca_cert_store;
        CmsSignedDataGenerator signed_gen;
        CmsProcessable enveloped_content;
        CmsSignedData signed_data;

        recipient_bc_cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(recipient_cert.RawData);
        enveloped_gen = new CmsEnvelopedDataGenerator(new SecureRandom());
        AddRecipient(enveloped_gen, recipient_bc_cert);
        enveloped = enveloped_gen.Generate(new CmsProcessableByteArray(degenerate_bytes), CmsEnvelopedGenerator.Aes128Cbc);
        enveloped_bytes = enveloped.GetEncoded();

        signed_attrs_dict = new Dictionary<DerObjectIdentifier, object>();
        signed_attrs_dict[new DerObjectIdentifier(OidMessageType)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidMessageType), new DerSet(new DerPrintableString(message_type)));
        signed_attrs_dict[new DerObjectIdentifier(OidPkiStatus)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidPkiStatus), new DerSet(new DerPrintableString(pki_status)));
        signed_attrs_dict[new DerObjectIdentifier(OidTransId)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidTransId), new DerSet(new DerPrintableString(trans_id)));
        signed_attrs_dict[new DerObjectIdentifier(OidRecipientNonce)] = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(OidRecipientNonce), new DerSet(new DerOctetString(recipient_nonce)));
        signed_attr_table = new Org.BouncyCastle.Asn1.Cms.AttributeTable(signed_attrs_dict);

        ca_cert_store = CollectionUtilities.CreateStore(new[] { Certificate });
        signed_gen = new CmsSignedDataGenerator(new SecureRandom());
        signed_gen.AddSignerInfoGenerator(BuildCaSigner(signed_attr_table));
        signed_gen.AddCertificates(ca_cert_store);

        enveloped_content = new CmsProcessableByteArray(enveloped_bytes);
        signed_data = signed_gen.Generate(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.EnvelopedData.Id, enveloped_content, true);
        return signed_data.GetEncoded();
    }

    // Choose the CertRep envelope RecipientInfo by the requester certificate's key algorithm, mirroring
    // the client-side request envelope: RSA -> key transport; EC -> ephemeral-static ECDH key agreement
    // (KeyAgreeRecipientInfo). Without the EC arm, enrolling an EC *subject* key fails here, because the
    // response is always enveloped back to the requester's own (EC) self-signed signer certificate.
    private static void AddRecipient(CmsEnvelopedDataGenerator generator, Org.BouncyCastle.X509.X509Certificate recipient_bc_cert) {
        const string OidEc = "1.2.840.10045.2.1";
        string algorithm_oid;

        algorithm_oid = recipient_bc_cert.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm.Id;
        if (algorithm_oid == OidEc) {
            Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters recipient_public;
            ECKeyPairGenerator ec_generator;
            AsymmetricCipherKeyPair ephemeral;

            recipient_public = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)recipient_bc_cert.GetPublicKey();
            ec_generator = new ECKeyPairGenerator("ECDH");
            ec_generator.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(recipient_public.Parameters, new SecureRandom()));
            ephemeral = ec_generator.GenerateKeyPair();
            generator.AddKeyAgreementRecipient(
                CmsEnvelopedGenerator.ECDHSha256Kdf,
                ephemeral.Private,
                ephemeral.Public,
                recipient_bc_cert,
                CmsEnvelopedGenerator.Aes128Wrap);
        } else {
            generator.AddKeyTransRecipient(recipient_bc_cert);
        }
    }

    /// <summary>
    /// Handles a PKCSReq/RenewalReq: decrypts the request, issues a certificate for the enclosed CSR, and
    /// returns a SUCCESS CertRep enveloped back to the request's signer — or a signed failure CertRep with
    /// the RFC-expected failInfo for the first detectable fault.
    /// </summary>
    /// <param name="pkcs_req_der">The DER-encoded SCEP PKIOperation request.</param>
    /// <returns>The DER-encoded SCEP CertRep response.</returns>
    public byte[] HandlePkiOperation(byte[] pkcs_req_der) {
        CmsSignedData signed;
        SignerInformation signer;
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] sender_nonce;
        byte[] inner_payload;
        System.DateTime? signing_time;

        signed = new CmsSignedData(pkcs_req_der);
        signer = First(signed);

        // 1. Signature integrity -> badMessageCheck ("1").
        if (!VerifyOuterSignature(pkcs_req_der)) {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "1");
        }

        // 2. signingTime window (+-5 min) -> badTime ("3").
        signing_time = ReadSigningTime(pkcs_req_der);
        if (signing_time.HasValue && System.Math.Abs((DateTime.UtcNow - signing_time.Value).TotalMinutes) > 5) {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "3");
        }

        // 3. Forbidden digest (MD5) -> badAlg ("0").
        if (signer.DigestAlgorithmID.Algorithm.Id == "1.2.840.113549.2.5") {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "0");
        }

        // 4. Inner CSR must parse -> badRequest ("2").
        if (!InnerCsrParses(pkcs_req_der)) {
            return BuildFailureCertRep(RecipientFrom(signed, signer), TransIdFrom(signer), NonceFrom(signer), "2");
        }

        DecodeRequest(pkcs_req_der, out requester_cert, out trans_id, out sender_nonce, out inner_payload);

        // 5. Challenge password -> FAILURE with badRequest ("2") if required and not satisfied.
        //    A static --challenge must match; NDES mode accepts (and consumes, one-time) a challenge
        //    the mscep_admin page issued.
        if (ExpectedChallenge != null || NdesMode) {
            string presented;
            bool challenge_ok;

            presented = ChallengeFrom(inner_payload);
            challenge_ok = (ExpectedChallenge != null && presented == ExpectedChallenge);
            if (!challenge_ok && NdesMode) {
                lock (_ndes_challenges) { challenge_ok = _ndes_challenges.Remove(presented); }
            }
            if (!challenge_ok) {
                return BuildFailureCertRep(requester_cert, trans_id, sender_nonce, "2");
            }
        }

        // 6. Expired signer cert (mirror a real CA refusing to renew off an expired cert).
        if (SignerCertExpired(requester_cert)) {
            return BuildFailureCertRep(requester_cert, trans_id, sender_nonce, "2");
        }

        // 7. PENDING mode.
        if (PendingMode) {
            return BuildPendingCertRep(requester_cert, trans_id, sender_nonce);
        }

        // Success.
        return IssueAndBuildSuccess(inner_payload, requester_cert, trans_id, sender_nonce);
    }

    private X509Certificate2 RecipientFrom(CmsSignedData signed, SignerInformation signer) {
        return new X509Certificate2(FirstCert(signed, signer).GetEncoded());
    }

    private static string TransIdFrom(SignerInformation signer) {
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;
        Org.BouncyCastle.Asn1.Cms.Attribute? tx_a;

        attrs = signer.SignedAttributes;
        if (attrs is null) { return "tx"; }
        tx_a = attrs[new DerObjectIdentifier(OidTransId)];
        if (tx_a is null) { return "tx"; }
        return ((DerPrintableString)tx_a.AttrValues[0]).GetString();
    }

    private static byte[] NonceFrom(SignerInformation signer) {
        const string OidSenderNonce = "2.16.840.1.113733.1.9.5";
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;
        Org.BouncyCastle.Asn1.Cms.Attribute? n_a;

        attrs = signer.SignedAttributes;
        if (attrs is null) { return new byte[16]; }
        n_a = attrs[new DerObjectIdentifier(OidSenderNonce)];
        if (n_a is null) { return new byte[16]; }
        return ((Asn1OctetString)n_a.AttrValues[0]).GetOctets();
    }

    private static string ChallengeFrom(byte[] csr_der) {
        const string OidChallengePassword = "1.2.840.113549.1.9.7";
        Pkcs10CertificationRequest csr;
        CertificationRequestInfo info;
        Asn1Set attributes;

        csr = new Pkcs10CertificationRequest(csr_der);
        info = csr.GetCertificationRequestInfo();
        attributes = info.Attributes;
        if (attributes is null) { return string.Empty; }

        foreach (Asn1Encodable encodable in attributes) {
            AttributePkcs attr;

            attr = AttributePkcs.GetInstance(encodable);
            if (attr.AttrType.Id == OidChallengePassword && attr.AttrValues.Count > 0) {
                return ((IAsn1String)attr.AttrValues[0]).GetString();
            }
        }
        return string.Empty;
    }

    private static bool SignerCertExpired(X509Certificate2 signer_cert) {
        return signer_cert.NotAfter < DateTime.UtcNow;
    }

    private byte[] IssueAndBuildSuccess(byte[] csr_der, X509Certificate2 requester_cert, string trans_id, byte[] sender_nonce) {
        Pkcs10CertificationRequest csr;
        AsymmetricKeyParameter csr_public_key;
        string subject_dn;
        Org.BouncyCastle.X509.X509Certificate issued;

        csr = new Pkcs10CertificationRequest(csr_der);
        csr_public_key = csr.GetPublicKey();
        subject_dn = csr.GetCertificationRequestInfo().Subject.ToString();

        issued = Issue(csr_public_key, subject_dn, RequestedSan(csr), RequestedEku(csr));
        return BuildSuccessCertRep(issued, requester_cert, trans_id, sender_nonce);
    }

    // Pull a SubjectAltName out of the CSR's PKCS#9 extensionRequest attribute, if the client put one there.
    private static Org.BouncyCastle.Asn1.X509.X509Extension? RequestedSan(Pkcs10CertificationRequest csr) {
        return RequestedExtension(csr, X509Extensions.SubjectAlternativeName);
    }

    // Pull a requested ExtendedKeyUsage out of the CSR's extensionRequest, mirroring RequestedSan — so
    // the issued leaf honors the EKU the client asked for instead of the hardcoded clientAuth default.
    private static Org.BouncyCastle.Asn1.X509.X509Extension? RequestedEku(Pkcs10CertificationRequest csr) {
        return RequestedExtension(csr, X509Extensions.ExtendedKeyUsage);
    }

    private static Org.BouncyCastle.Asn1.X509.X509Extension? RequestedExtension(Pkcs10CertificationRequest csr, DerObjectIdentifier oid) {
        Org.BouncyCastle.Asn1.Pkcs.CertificationRequestInfo info;
        Asn1Set attributes;

        info = csr.GetCertificationRequestInfo();
        attributes = info.Attributes;
        if (attributes == null) { return null; }

        foreach (Asn1Encodable encodable in attributes) {
            Org.BouncyCastle.Asn1.Pkcs.AttributePkcs attr;

            attr = Org.BouncyCastle.Asn1.Pkcs.AttributePkcs.GetInstance(encodable);
            if (attr.AttrType.Equals(Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtExtensionRequest)) {
                X509Extensions extensions;

                extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                return extensions.GetExtension(oid);
            }
        }
        return null;
    }

    internal bool VerifyOuterSignature(byte[] der) {
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.X509.X509Certificate signer_cert;

        signed = new CmsSignedData(der);
        signer = First(signed);
        signer_cert = FirstCert(signed, signer);
        try {
            return signer.Verify(signer_cert.GetPublicKey());
        } catch (System.Exception) {
            return false;
        }
    }

    internal System.DateTime? ReadSigningTime(byte[] der) {
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute? attr;

        signed = new CmsSignedData(der);
        signer = First(signed);
        if (signer.SignedAttributes == null) { return null; }
        attr = signer.SignedAttributes[new DerObjectIdentifier("1.2.840.113549.1.9.5")];
        if (attr == null) { return null; }
        return Org.BouncyCastle.Asn1.Cms.Time.GetInstance(attr.AttrValues[0]).ToDateTime();
    }

    internal bool InnerCsrParses(byte[] der) {
        byte[] inner;
        Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest parsed;

        try {
            inner = DecryptInner(der);
            parsed = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(inner);
            return parsed.Verify();
        } catch (System.Exception) {
            return false;
        }
    }

    private static SignerInformation First(CmsSignedData signed) {
        return signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
    }

    private static Org.BouncyCastle.X509.X509Certificate FirstCert(CmsSignedData signed, SignerInformation signer) {
        return signed.GetCertificates().EnumerateMatches(signer.SignerID).Cast<Org.BouncyCastle.X509.X509Certificate>().First();
    }

    private byte[] DecryptInner(byte[] der) {
        CmsSignedData signed;
        MemoryStream env_stream;

        signed = new CmsSignedData(der);
        env_stream = new MemoryStream();
        signed.SignedContent.Write(env_stream);
        return DecryptEnvelopedData(env_stream.ToArray());
    }

    // Decrypts the SCEP inner EnvelopedData. ML-KEM recipients use the hand-rolled RFC 9629 path
    // (BC has no CMS KEM recipient); RSA/EC use the standard recipient API.
    private byte[] DecryptEnvelopedData(byte[] env_der) {
        Org.BouncyCastle.Crypto.Parameters.MLKemPrivateKeyParameters? mlkem_priv;

        mlkem_priv = _encryption_key?.Private as Org.BouncyCastle.Crypto.Parameters.MLKemPrivateKeyParameters;
        if (mlkem_priv != null) {
            return KemEnvelopeDecrypt.Decrypt(env_der, mlkem_priv);
        }
        return new CmsEnvelopedData(env_der).GetRecipientInfos().GetRecipients().Cast<RecipientInformation>().First().GetContent(RecipientKey);
    }

    /// <summary>Reads the SCEP messageType signed attribute from a request without otherwise processing it.</summary>
    /// <param name="der">The DER-encoded SCEP request.</param>
    /// <returns>The messageType value (e.g. <c>"19"</c>, <c>"20"</c>, <c>"21"</c>, <c>"22"</c>), or an empty string if absent.</returns>
    public string PeekMessageType(byte[] der) {
        const string OidMessageType = "2.16.840.1.113733.1.9.2";
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.Asn1.Cms.Attribute? attr;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        attr = signer.SignedAttributes?[new DerObjectIdentifier(OidMessageType)];
        return attr is null ? string.Empty : ((DerPrintableString)attr.AttrValues[0]).GetString();
    }

    /// <summary>Handles a GetCert request: returns the previously issued certificate for the requested issuer/serial as a CertRep, or a failure CertRep if not found.</summary>
    /// <param name="der">The DER-encoded SCEP GetCert request.</param>
    /// <returns>The DER-encoded SCEP CertRep response.</returns>
    public byte[] HandleGetCert(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        byte[] inner;
        Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber ias;
        string serial_key;
        Org.BouncyCastle.X509.X509Certificate? found;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out inner);
        ias = Org.BouncyCastle.Asn1.Cms.IssuerAndSerialNumber.GetInstance(Asn1Object.FromByteArray(inner));
        serial_key = ias.SerialNumber.Value.ToString(16).ToUpperInvariant();

        if (!_issued_by_serial.TryGetValue(serial_key, out found)) {
            return BuildFailureCertRep(requester_cert, trans_id, nonce, "4");
        }
        return BuildSuccessCertRep(found, requester_cert, trans_id, nonce);
    }

    /// <summary>Handles a GetCRL request: returns the CA's CRL wrapped in a CertRep.</summary>
    /// <param name="der">The DER-encoded SCEP GetCRL request.</param>
    /// <returns>The DER-encoded SCEP CertRep response carrying the CRL.</returns>
    public byte[] HandleGetCrl(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        byte[] inner;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out inner);
        return BuildSuccessCrlRep(GenerateCrl(), requester_cert, trans_id, nonce);
    }

    private void DecodeRequest(byte[] der, out X509Certificate2 requester_cert, out string trans_id, out byte[] sender_nonce, out byte[] inner_payload) {
        const string OidTransId = "2.16.840.1.113733.1.9.7";
        const string OidSenderNonce = "2.16.840.1.113733.1.9.5";
        CmsSignedData signed;
        SignerInformation signer;
        Org.BouncyCastle.X509.X509Certificate signer_bc_cert;
        MemoryStream env_stream;
        Org.BouncyCastle.Asn1.Cms.AttributeTable attrs;

        signed = new CmsSignedData(der);
        signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        signer_bc_cert = signed.GetCertificates().EnumerateMatches(signer.SignerID).Cast<Org.BouncyCastle.X509.X509Certificate>().First();
        requester_cert = new X509Certificate2(signer_bc_cert.GetEncoded());

        env_stream = new MemoryStream();
        signed.SignedContent.Write(env_stream);
        inner_payload = DecryptEnvelopedData(env_stream.ToArray());

        trans_id = "tx";
        sender_nonce = new byte[16];
        attrs = signer.SignedAttributes;
        if (attrs is not null) {
            Org.BouncyCastle.Asn1.Cms.Attribute? tx_a;
            Org.BouncyCastle.Asn1.Cms.Attribute? n_a;

            tx_a = attrs[new DerObjectIdentifier(OidTransId)];
            n_a = attrs[new DerObjectIdentifier(OidSenderNonce)];
            if (tx_a is not null) { trans_id = ((DerPrintableString)tx_a.AttrValues[0]).GetString(); }
            if (n_a is not null) { sender_nonce = ((Asn1OctetString)n_a.AttrValues[0]).GetOctets(); }
        }
    }

    /// <summary>Handles a CertPoll request: returns the issued certificate as a CertRep once available, or a PENDING/failure CertRep otherwise.</summary>
    /// <param name="der">The DER-encoded SCEP CertPoll request.</param>
    /// <returns>The DER-encoded SCEP CertRep response.</returns>
    public byte[] HandlePoll(byte[] der) {
        X509Certificate2 requester_cert;
        string trans_id;
        byte[] nonce;
        byte[] inner;
        Asn1Sequence ias;
        Org.BouncyCastle.Asn1.X509.X509Name subject_name;
        Org.BouncyCastle.X509.X509Certificate issued;

        DecodeRequest(der, out requester_cert, out trans_id, out nonce, out inner);

        if (PendingMode) {
            return BuildPendingCertRep(requester_cert, trans_id, nonce);
        }

        ias = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(inner));
        subject_name = Org.BouncyCastle.Asn1.X509.X509Name.GetInstance(ias[1]);

        issued = Issue(new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(requester_cert.RawData).GetPublicKey(), subject_name.ToString());
        return BuildSuccessCertRep(issued, requester_cert, trans_id, nonce);
    }
}
