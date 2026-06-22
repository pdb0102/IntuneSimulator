using System;
using System.Linq;

namespace ScepWright.Crypto;

// Provider-agnostic pre-flight: before a PkiMessage is handed to a provider's EncodePkiMessage,
// confirm the loaded provider's advertised CryptoCapabilities actually cover the algorithms this
// message needs, so the tool fails cleanly with a helpful message instead of a raw provider-internal
// exception (important for external / under-capable providers). Recipient classification uses three
// local OID constants because this assembly cannot reference ScepWright.Core.Recipients.
internal static class CapabilityGuard {
    private const string OidRsa = "1.2.840.113549.1.1.1";
    private const string OidEc = "1.2.840.10045.2.1";
    private const string OidMlKemArc = "2.16.840.1.101.3.4.4.";

    public static bool Check(PkiMessage message, CryptoCapabilities caps, out string error) {
        error = string.Empty;

        if (message.SignerCert != null) {
            string signer_oid;

            if (!caps.Digests.Contains(message.DigestAlgorithmOid)) {
                error = $"loaded crypto provider does not support digest {Friendly(message.DigestAlgorithmOid)}";
                return false;
            }

            signer_oid = message.SignerCert.GetKeyAlgorithm();
            if (!caps.Signatures.Contains(signer_oid)) {
                error = $"loaded crypto provider does not support signing with {Friendly(signer_oid)}";
                return false;
            }
        }

        if (message.RecipientCaCert != null) {
            string recipient_oid;
            string kind;

            if (!caps.ContentEncryption.Contains(message.ContentEncryptionAlgorithmOid)) {
                error = $"loaded crypto provider does not support content cipher {Friendly(message.ContentEncryptionAlgorithmOid)}";
                return false;
            }

            recipient_oid = message.RecipientCaCert.GetKeyAlgorithm();
            if (!RecipientSupported(recipient_oid, caps, out kind)) {
                error = $"loaded crypto provider does not support enveloping to a {kind} recipient ({Friendly(recipient_oid)})";
                return false;
            }
        }

        return true;
    }

    private static bool RecipientSupported(string recipient_oid, CryptoCapabilities caps, out string kind) {
        if (recipient_oid == OidRsa) {
            kind = "RSA key-transport";
            return caps.KeyTransport.Contains(recipient_oid);
        }
        if (recipient_oid == OidEc) {
            kind = "EC key-agreement";
            return caps.KeyAgreement.Contains(recipient_oid);
        }
        if (recipient_oid.StartsWith(OidMlKemArc, StringComparison.Ordinal)) {
            kind = "ML-KEM KEMRecipientInfo";
            return caps.Kem.Contains(recipient_oid);
        }
        kind = "unknown-algorithm";
        return false;
    }

    private static string Friendly(string oid) => Algorithms.NameFor(oid) ?? oid;
}
