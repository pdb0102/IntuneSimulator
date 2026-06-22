using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ScepWright.Core;
using ScepWright.Crypto;

namespace ScepWright.Core.Storage;

/// <summary>On-disk store of issued certificates and their private keys, keyed by server and thumbprint.</summary>
public sealed class CertStore {
    private readonly string _root;

    /// <summary>Creates a store rooted at the given data directory.</summary>
    public CertStore(string root) {
        _root = root;
    }

    /// <summary>Saves a freshly enrolled certificate and its key from the originating <see cref="EnrollRequest"/>.</summary>
    public string Save(string server_id, X509Certificate2 cert, EnrollRequest request, IScepCrypto crypto) {
        return Save(server_id, cert, request.Key, crypto,
            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: null,
            key_spec_text: request.KeySpecText);
    }

    /// <summary>
    /// Saves a certificate, its key, and metadata. The key is written encrypted when
    /// <paramref name="passphrase"/> is supplied (and any plaintext copy is removed), otherwise as
    /// plaintext PKCS#8. Returns the cert id (lowercased thumbprint).
    /// </summary>
    public string Save(string server_id, X509Certificate2 cert, IScepKey key, IScepCrypto crypto,
                       string? challenge_password, string? renewed_from, string? transaction_id, string? passphrase = null,
                       string? key_spec_text = null) {
        string cert_id;
        string cert_dir;
        string plain_path;
        string enc_path;
        byte[] key_der;
        string key_error;
        CertRecord metadata;

        cert_id = cert.Thumbprint.ToLowerInvariant();
        cert_dir = Path.Combine(_root, "servers", server_id, "certificates", cert_id);
        Directory.CreateDirectory(cert_dir);

        File.WriteAllText(Path.Combine(cert_dir, "cert.pem"), cert.ExportCertificatePem());

        plain_path = Path.Combine(cert_dir, "key.pkcs8");
        enc_path = Path.Combine(cert_dir, "key.pkcs8.enc");

        if (!string.IsNullOrEmpty(passphrase)) {
            if (crypto.ExportPrivateKeyPkcs8Encrypted(key, passphrase!, out key_der, out key_error)) {
                if (File.Exists(plain_path)) { File.Delete(plain_path); }
                File.WriteAllBytes(enc_path, key_der);
            }
        } else if (crypto.ExportPrivateKeyPkcs8(key, out key_der, out key_error)) {
            if (File.Exists(enc_path)) { File.Delete(enc_path); }
            File.WriteAllBytes(plain_path, key_der);
        }

        metadata = new CertRecord {
            Subject = cert.Subject,
            Serial = cert.SerialNumber,
            // X509Certificate2 returns local time; persist UTC so it is never mislabeled on display.
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            Thumbprint = cert.Thumbprint,
            ChallengePasswordHash = challenge_password != null ? Redaction.Hash(challenge_password) : null,
            RenewedFrom = renewed_from,
            TransactionId = transaction_id,
            KeySpec = key_spec_text,
            Status = "issued",
        };

        File.WriteAllText(Path.Combine(cert_dir, "metadata.json"), JsonSerializer.Serialize(metadata));
        return cert_id;
    }

    /// <summary>
    /// Loads a stored certificate, its key, and metadata. A <paramref name="passphrase"/> is required
    /// if the key was stored encrypted.
    /// </summary>
    public bool Load(string server_id, string cert_id, IScepCrypto crypto,
                    out X509Certificate2 cert, out IScepKey key, out CertRecord record, out string error, string? passphrase = null) {
        string cert_dir;
        string key_path;
        string enc_path;

        cert = null!;
        key = null!;
        record = null!;
        error = string.Empty;

        cert_dir = Path.Combine(_root, "servers", server_id, "certificates", cert_id);
        if (!Directory.Exists(cert_dir)) {
            error = $"no stored certificate '{cert_id}' under server '{server_id}'";
            return false;
        }

        cert = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(cert_dir, "cert.pem")));

        key_path = Path.Combine(cert_dir, "key.pkcs8");
        enc_path = Path.Combine(cert_dir, "key.pkcs8.enc");
        if (File.Exists(enc_path)) {
            if (string.IsNullOrEmpty(passphrase)) {
                error = $"certificate '{cert_id}' has an encrypted key; a passphrase is required";
                return false;
            }
            if (!crypto.ImportPrivateKeyPkcs8Encrypted(File.ReadAllBytes(enc_path), passphrase!, out key, out error)) {
                return false;
            }
        } else if (File.Exists(key_path)) {
            if (!crypto.ImportPrivateKeyPkcs8(File.ReadAllBytes(key_path), out key, out error)) {
                return false;
            }
        } else {
            error = $"no stored key for certificate '{cert_id}'";
            return false;
        }

        record = JsonSerializer.Deserialize<CertRecord>(File.ReadAllText(Path.Combine(cert_dir, "metadata.json")))!;
        return true;
    }

    /// <summary>Returns whether the stored key for the given certificate is encrypted at rest.</summary>
    public bool IsKeyEncrypted(string server_id, string cert_id) {
        return File.Exists(Path.Combine(_root, "servers", server_id, "certificates", cert_id, "key.pkcs8.enc"));
    }

    /// <summary>Finds the server id that owns the given certificate, or null if not found.</summary>
    public string? FindServerForCert(string cert_id) {
        string servers_root;
        string[] server_dirs;

        // A blank id would otherwise collapse to the certificates/ directory and match an arbitrary server.
        if (string.IsNullOrEmpty(cert_id)) { return null; }
        servers_root = Path.Combine(_root, "servers");
        if (!Directory.Exists(servers_root)) {
            return null;
        }

        server_dirs = Directory.GetDirectories(servers_root);
        foreach (string server_dir in server_dirs) {
            if (Directory.Exists(Path.Combine(server_dir, "certificates", cert_id))) {
                return Path.GetFileName(server_dir);
            }
        }
        return null;
    }

    /// <summary>Persisted metadata about a stored certificate.</summary>
    public sealed class CertRecord {
        /// <summary>Gets or sets the subject DN.</summary>
        public string Subject { get; set; } = string.Empty;
        /// <summary>Gets or sets the serial number.</summary>
        public string Serial { get; set; } = string.Empty;
        /// <summary>Gets or sets the not-before validity bound (UTC).</summary>
        public DateTime NotBefore { get; set; }
        /// <summary>Gets or sets the not-after validity bound (UTC).</summary>
        public DateTime NotAfter { get; set; }
        /// <summary>Gets or sets the SHA-1 thumbprint.</summary>
        public string Thumbprint { get; set; } = string.Empty;
        /// <summary>Gets or sets the salted hash of the challenge password (never the plaintext).</summary>
        public string? ChallengePasswordHash { get; set; }
        /// <summary>Gets or sets the cert id this one was renewed from, for lineage.</summary>
        public string? RenewedFrom { get; set; }
        /// <summary>Gets or sets the SCEP transaction id of the issuing request.</summary>
        public string? TransactionId { get; set; }
        /// <summary>Gets or sets the key spec the certificate was enrolled with.</summary>
        public string? KeySpec { get; set; }
        /// <summary>Gets or sets the lifecycle status. Defaults to "issued".</summary>
        public string Status { get; set; } = "issued";
    }
}
