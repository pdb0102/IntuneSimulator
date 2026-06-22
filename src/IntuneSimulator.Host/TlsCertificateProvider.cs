using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IntuneSimulator.Host;

/// <summary>Resolves the TLS certificate Kestrel uses for HTTPS, generating and persisting a self-signed one when none is supplied.</summary>
public static class TlsCertificateProvider
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1"; // id-kp-serverAuth
    private const string SubjectAltNameOid = "2.5.29.17";
    private const string PfxPassword = "sim";

    /// <summary>
    /// Returns a cert with private key for Kestrel HTTPS: a BYO cert if a path is given, otherwise a
    /// persisted self-signed one. The self-signed cert is generated with the attributes a server cert
    /// needs to validate cleanly once installed in a Trusted Root store (CA basic constraint, key usage,
    /// serverAuth EKU, and localhost/loopback/hostname SANs).
    /// </summary>
    /// <param name="certDir">Override the directory the self-signed cert is persisted to (testing). Null = alongside the executable.</param>
    public static X509Certificate2 Resolve(HostConfig cfg, string? certDir = null)
    {
        if (!string.IsNullOrEmpty(cfg.TlsCertPath))
            return new X509Certificate2(cfg.TlsCertPath!, cfg.TlsCertPassword, X509KeyStorageFlags.Exportable);

        string dir = certDir ?? Path.Combine(AppContext.BaseDirectory, "sim-tls");
        Directory.CreateDirectory(dir);
        string pfxPath = Path.Combine(dir, "sim-cert.pfx");
        string cerPath = Path.Combine(dir, "sim-cert.cer");

        if (File.Exists(pfxPath))
        {
            X509Certificate2 existing = new X509Certificate2(pfxPath, PfxPassword, X509KeyStorageFlags.Exportable);

            // Reuse a previously-generated cert only if it already carries the hardened attributes; an older
            // minimal cert (no serverAuth EKU) is regenerated so trust works without manual cleanup.
            if (HasServerAuthEku(existing))
                return existing;

            existing.Dispose();
        }

        X509Certificate2 generated = CreateSelfSigned();
        byte[] pfxBytes = generated.Export(X509ContentType.Pfx, PfxPassword);

        File.WriteAllBytes(pfxPath, pfxBytes);
        File.WriteAllBytes(cerPath, generated.Export(X509ContentType.Cert));
        generated.Dispose();

        // Round-trip through the PFX so Kestrel/SChannel gets a persisted, usable private key.
        return new X509Certificate2(pfxBytes, PfxPassword, X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 CreateSelfSigned()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest req = new CertificateRequest("CN=Intune Simulator", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Self-signed cert doubles as its own trust anchor once placed in a Trusted Root store.
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyCertSign,
            critical: true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(ServerAuthOid, "Server Authentication") }, critical: false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));

        SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);     // 127.0.0.1
        san.AddIpAddress(IPAddress.IPv6Loopback); // ::1
        AddHostName(san);
        req.CertificateExtensions.Add(san.Build());

        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    private static void AddHostName(SubjectAlternativeNameBuilder san)
    {
        try
        {
            string host = Dns.GetHostName();

            if (!string.IsNullOrWhiteSpace(host) && !string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
                san.AddDnsName(host);
        }
        catch
        {
            // Hostname unavailable — localhost + loopback SANs are sufficient for local testing.
        }
    }

    private static bool HasServerAuthEku(X509Certificate2 cert)
    {
        foreach (X509Extension ext in cert.Extensions)
        {
            if (ext is X509EnhancedKeyUsageExtension eku)
            {
                foreach (Oid oid in eku.EnhancedKeyUsages)
                {
                    if (oid.Value == ServerAuthOid)
                        return true;
                }
            }
        }

        return false;
    }
}
