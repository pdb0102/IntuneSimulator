using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace ScepWright.Core.Recipients;

/// <summary>How a candidate certificate's key would be used as the SCEP EnvelopedData recipient.</summary>
public enum RecipientKind {
    /// <summary>RSA key-transport (key encipherment).</summary>
    KeyTransport,
    /// <summary>EC key-agreement (ECDH).</summary>
    KeyAgreement,
    /// <summary>Post-quantum key encapsulation (ML-KEM).</summary>
    Kem,
    /// <summary>Signature-only key; cannot be an envelope recipient.</summary>
    SignatureOnly,
    /// <summary>Unrecognized algorithm.</summary>
    Unknown
}

/// <summary>
/// Strategy for distinguishing RA signing/encryption certs in a GetCACert bundle. RFC 8894 leaves
/// this undefined: <see cref="KeyUsage"/> is the semantically-correct default; <see cref="Positional"/>
/// reproduces the NDES-style convention some servers/clients rely on.
/// </summary>
public enum RecipientStrategy {
    /// <summary>Select by the certificate's KeyUsage bits.</summary>
    KeyUsage,
    /// <summary>Select by position (first = signing, second = encryption).</summary>
    Positional
}

/// <summary>A conformance observation about recipient selection, with a stable code and a message.</summary>
public sealed record RecipientFinding(string Code, string Message);

/// <summary>The outcome of selecting SCEP signing and encryption certificates from a CA bundle.</summary>
public sealed class RecipientSelection {
    /// <summary>Gets the chosen signing certificate, if any.</summary>
    public X509Certificate2? SigningCertificate { get; init; }
    /// <summary>Gets the chosen envelope-encryption certificate, if any.</summary>
    public X509Certificate2? EncryptionCertificate { get; init; }
    /// <summary>Gets the kind of the chosen encryption certificate.</summary>
    public RecipientKind EncryptionKind { get; init; } = RecipientKind.Unknown;
    /// <summary>Gets the conformance findings recorded during selection.</summary>
    public IReadOnlyList<RecipientFinding> Findings { get; init; } = Array.Empty<RecipientFinding>();

    /// <summary>Gets whether a usable, encryption-capable recipient was selected.</summary>
    public bool CanEnvelope => EncryptionCertificate is not null
        && (EncryptionKind == RecipientKind.KeyTransport
            || EncryptionKind == RecipientKind.KeyAgreement
            || EncryptionKind == RecipientKind.Kem);
}

/// <summary>
/// Chooses the SCEP signing and encryption certificates from a GetCACert bundle and reports
/// conformance findings (e.g. a server presenting only signature-capable certs, or one whose
/// KeyUsage bits do not match the key's algorithm).
/// </summary>
public static class RecipientSelector {
    private const string OidRsa = "1.2.840.113549.1.1.1";
    private const string OidEc = "1.2.840.10045.2.1";
    private const string OidMlKemArc = "2.16.840.1.101.3.4.4.";
    private const string OidPqSignatureArc = "2.16.840.1.101.3.4.3.";   // ML-DSA + SLH-DSA signature arc

    /// <summary>Classifies a SubjectPublicKeyInfo algorithm OID into a <see cref="RecipientKind"/>.</summary>
    public static RecipientKind ClassifyAlgorithm(string spki_oid) {
        if (spki_oid == OidRsa) { return RecipientKind.KeyTransport; }
        if (spki_oid == OidEc) { return RecipientKind.KeyAgreement; }
        if (spki_oid.StartsWith(OidMlKemArc, StringComparison.Ordinal)) { return RecipientKind.Kem; }
        if (spki_oid.StartsWith(OidPqSignatureArc, StringComparison.Ordinal)) { return RecipientKind.SignatureOnly; }
        return RecipientKind.Unknown;
    }

    /// <summary>Selects the signing and encryption certificates from a CA bundle using the given strategy.</summary>
    public static RecipientSelection Select(IReadOnlyList<X509Certificate2> certs, RecipientStrategy strategy = RecipientStrategy.KeyUsage) {
        if (certs is null || certs.Count == 0) {
            return new RecipientSelection {
                Findings = new[] { new RecipientFinding("no-certificates", "GetCACert returned no certificates") },
            };
        }

        return strategy == RecipientStrategy.Positional ? SelectPositional(certs) : SelectByKeyUsage(certs);
    }

    private static RecipientSelection SelectByKeyUsage(IReadOnlyList<X509Certificate2> certs) {
        X509Certificate2? sign_cert;
        X509Certificate2? enc_cert;
        RecipientKind enc_kind;
        bool enc_capable_by_algorithm;
        bool enc_rejected_for_keyusage;
        List<RecipientFinding> findings;

        sign_cert = null;
        enc_cert = null;
        enc_kind = RecipientKind.Unknown;
        enc_capable_by_algorithm = false;
        enc_rejected_for_keyusage = false;
        findings = new List<RecipientFinding>();

        foreach (X509Certificate2 cert in certs) {
            string oid;
            RecipientKind kind;
            X509KeyUsageFlags? usage;

            oid = cert.GetKeyAlgorithm();
            kind = ClassifyAlgorithm(oid);
            usage = ReadKeyUsage(cert);

            if (sign_cert is null && CanSign(kind) && UsageAllowsSigning(usage)) {
                sign_cert = cert;
            }

            if (CanEncrypt(kind)) {
                enc_capable_by_algorithm = true;
                if (enc_cert is null) {
                    if (UsageAllowsEncryption(usage, kind)) {
                        enc_cert = cert;
                        enc_kind = kind;
                        if (usage is null) {
                            findings.Add(new RecipientFinding("no-keyusage-extension",
                                "encryption certificate has no KeyUsage extension; accepting on algorithm capability"));
                        }
                    } else {
                        enc_rejected_for_keyusage = true;
                    }
                }
            }
        }

        if (sign_cert is null && certs.Count > 0) {
            sign_cert = certs[0];
        }

        if (enc_cert is null) {
            if (enc_capable_by_algorithm && enc_rejected_for_keyusage) {
                findings.Add(new RecipientFinding("encryption-keyusage-missing",
                    "server's recipient key uses an encryption-capable algorithm (RSA/EC), but its KeyUsage permits neither keyEncipherment nor keyAgreement, so SCEP PKIOperation cannot be enveloped to it"));
            } else {
                findings.Add(new RecipientFinding("no-encryption-cert",
                    "server presents only signature-capable certificate(s); SCEP PKIOperation requires an encryption-capable recipient and cannot be enveloped"));
            }
        } else if (certs.Count > 1 && !ReferenceEquals(enc_cert, certs[1])) {
            findings.Add(new RecipientFinding("keyusage-position-mismatch",
                "the encryption certificate selected by KeyUsage is not the second certificate; position-based clients may pick the wrong one"));
        }

        return new RecipientSelection {
            SigningCertificate = sign_cert,
            EncryptionCertificate = enc_cert,
            EncryptionKind = enc_kind,
            Findings = findings,
        };
    }

    private static RecipientSelection SelectPositional(IReadOnlyList<X509Certificate2> certs) {
        X509Certificate2 sign_cert;
        X509Certificate2 enc_cert;
        RecipientKind enc_kind;
        List<RecipientFinding> findings;

        findings = new List<RecipientFinding>();
        sign_cert = certs[0];
        enc_cert = certs.Count > 1 ? certs[1] : certs[0];
        enc_kind = ClassifyAlgorithm(enc_cert.GetKeyAlgorithm());

        if (!CanEncrypt(enc_kind)) {
            findings.Add(new RecipientFinding("no-encryption-cert",
                "the positionally-selected encryption certificate is signature-only; PKIOperation cannot be enveloped"));
            return new RecipientSelection { SigningCertificate = sign_cert, Findings = findings };
        }

        return new RecipientSelection {
            SigningCertificate = sign_cert,
            EncryptionCertificate = enc_cert,
            EncryptionKind = enc_kind,
            Findings = findings,
        };
    }

    private static bool CanSign(RecipientKind kind) =>
        kind == RecipientKind.KeyTransport || kind == RecipientKind.KeyAgreement || kind == RecipientKind.SignatureOnly;

    private static bool CanEncrypt(RecipientKind kind) =>
        kind == RecipientKind.KeyTransport || kind == RecipientKind.KeyAgreement || kind == RecipientKind.Kem;

    private static bool UsageAllowsSigning(X509KeyUsageFlags? usage) =>
        usage is null
        || (usage.Value & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign)) != 0;

    private static bool UsageAllowsEncryption(X509KeyUsageFlags? usage, RecipientKind kind) {
        if (usage is null) { return true; }
        if (kind == RecipientKind.KeyAgreement) {
            return (usage.Value & X509KeyUsageFlags.KeyAgreement) != 0;
        }
        return (usage.Value & X509KeyUsageFlags.KeyEncipherment) != 0;
    }

    private static X509KeyUsageFlags? ReadKeyUsage(X509Certificate2 cert) {
        X509KeyUsageExtension? ext;

        ext = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        return ext?.KeyUsages;
    }
}
