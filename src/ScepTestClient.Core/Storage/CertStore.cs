using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ScepTestClient.Core;
using ScepTestClient.CryptoApi;

namespace ScepTestClient.Core.Storage;

public sealed class CertStore {
    private readonly string _root;

    public CertStore(string root) {
        _root = root;
    }

    // Phase 1 overload — unchanged signature, now delegates to the core overload.
    public string Save(string server_id, X509Certificate2 cert, EnrollRequest request, IScepCrypto crypto) {
        return Save(server_id, cert, request.Key, crypto,
            challenge_password: request.ChallengePassword, renewed_from: null, transaction_id: null);
    }

    public string Save(string server_id, X509Certificate2 cert, IScepKey key, IScepCrypto crypto,
                       string? challenge_password, string? renewed_from, string? transaction_id) {
        string cert_id;
        string cert_dir;
        byte[] key_der;
        string key_error;
        CertRecord metadata;

        cert_id = cert.Thumbprint.ToLowerInvariant();
        cert_dir = Path.Combine(_root, "servers", server_id, "certificates", cert_id);
        Directory.CreateDirectory(cert_dir);

        File.WriteAllText(Path.Combine(cert_dir, "cert.pem"), cert.ExportCertificatePem());

        if (crypto.ExportPrivateKeyPkcs8(key, out key_der, out key_error)) {
            File.WriteAllBytes(Path.Combine(cert_dir, "key.pkcs8"), key_der);
        }

        metadata = new CertRecord {
            Subject = cert.Subject,
            Serial = cert.SerialNumber,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprint = cert.Thumbprint,
            ChallengePasswordHash = challenge_password != null ? Redaction.Hash(challenge_password) : null,
            RenewedFrom = renewed_from,
            TransactionId = transaction_id,
            Status = "issued",
        };

        File.WriteAllText(Path.Combine(cert_dir, "metadata.json"), JsonSerializer.Serialize(metadata));
        return cert_id;
    }

    public bool Load(string server_id, string cert_id, IScepCrypto crypto,
                    out X509Certificate2 cert, out IScepKey key, out CertRecord record, out string error) {
        string cert_dir;
        string key_path;
        byte[] key_der;

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
        if (!File.Exists(key_path)) {
            error = $"no stored key for certificate '{cert_id}'";
            return false;
        }
        key_der = File.ReadAllBytes(key_path);
        if (!crypto.ImportPrivateKeyPkcs8(key_der, out key, out error)) {
            return false;
        }

        record = JsonSerializer.Deserialize<CertRecord>(File.ReadAllText(Path.Combine(cert_dir, "metadata.json")))!;
        return true;
    }

    public string? FindServerForCert(string cert_id) {
        string servers_root;
        string[] server_dirs;

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

    public sealed class CertRecord {
        public string Subject { get; set; } = string.Empty;
        public string Serial { get; set; } = string.Empty;
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string Thumbprint { get; set; } = string.Empty;
        public string? ChallengePasswordHash { get; set; }
        public string? RenewedFrom { get; set; }
        public string? TransactionId { get; set; }
        public string Status { get; set; } = "issued";
    }
}
