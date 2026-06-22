using System.Collections.Generic;
using System.Linq;
using ScepWright.Core.Protocol;
using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>Suggests concrete <c>scepclient enroll</c> command lines tailored to a server's advertised capabilities.</summary>
public static class ServerSuggest {
    /// <summary>Suggests commands using only the server's SCEP capabilities.</summary>
    public static IReadOnlyList<string> For(string server_id, ScepCapabilities caps) {
        return For(server_id, caps, new CryptoCapabilities());
    }

    /// <summary>Suggests commands also factoring in the loaded provider's crypto capabilities.</summary>
    public static IReadOnlyList<string> For(string server_id, ScepCapabilities caps, CryptoCapabilities crypto_caps) {
        return For(server_id, caps, crypto_caps, 2048);
    }

    /// <summary>Suggests commands, using <paramref name="min_rsa_bits"/> for the RSA key size in the examples.</summary>
    public static IReadOnlyList<string> For(string server_id, ScepCapabilities caps, CryptoCapabilities crypto_caps, int min_rsa_bits) {
        List<string> lines;
        List<string> digests;
        List<string> ciphers;
        string rsa_spec;

        rsa_spec = $"rsa:{min_rsa_bits}";

        lines = new List<string>();
        digests = new List<string>();
        ciphers = new List<string>();

        if (caps.Sha256) { digests.Add("SHA-256"); }
        if (caps.Sha512) { digests.Add("SHA-512"); }
        if (caps.Sha1) { digests.Add("SHA-1"); }
        if (digests.Count == 0) { digests.Add("SHA-256"); }

        if (caps.Aes) { ciphers.Add("AES-128-CBC"); }
        if (caps.Des3) { ciphers.Add("DES-EDE3-CBC"); }
        if (ciphers.Count == 0) { ciphers.Add("AES-128-CBC"); }

        foreach (string digest in digests) {
            foreach (string cipher in ciphers) {
                lines.Add($"scepclient enroll {server_id} --subject \"CN=test\" --key-spec {rsa_spec} --digest {digest} --cipher {cipher}{WeaknessNote(digest, cipher)}");
            }
        }

        if (crypto_caps.Signatures.Contains("1.2.840.10045.2.1")) {
            lines.Add($"scepclient enroll {server_id} --subject \"CN=test\" --key-spec ec:p256 --digest {digests[0]} --cipher {ciphers[0]}{WeaknessNote(digests[0], ciphers[0])}");
        }
        if (crypto_caps.PqTiers.TierA) {
            lines.Add($"scepclient enroll {server_id} --subject \"CN=test\" --key-spec ml-dsa:65 --digest {digests[0]} --cipher {ciphers[0]}{WeaknessNote(digests[0], ciphers[0])}");
        }
        if (crypto_caps.PqTiers.TierB) {
            lines.Add($"scepclient enroll {server_id} --subject \"CN=test\" --key-spec slh-dsa:192f --digest {digests[0]} --cipher {ciphers[0]}{WeaknessNote(digests[0], ciphers[0])}");
        }
        // ML-KEM (Tier C) is deliberately NOT suggested: a KEM cannot be a signing/subject key, so there
        // is no usable `enroll --key-spec ml-kem` command and it would only mislead.
        return lines;
    }

    // Inline weakness flag so suggested legacy algorithms read as interop fallbacks, not neutral choices.
    private static string WeaknessNote(string digest, string cipher) {
        if (digest == "SHA-1") { return "  # SHA-1 is cryptographically weak — interop only; prefer SHA-256"; }
        if (cipher == "DES-EDE3-CBC") { return "  # 3DES is weak — interop only; prefer AES"; }
        return string.Empty;
    }
}
