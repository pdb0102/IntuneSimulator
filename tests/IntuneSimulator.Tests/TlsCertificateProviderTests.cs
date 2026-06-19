using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IntuneSimulator.Host;
using Xunit;

namespace IntuneSimulator.Tests;

public class TlsCertificateProviderTests
{
    [Fact]
    public void Generated_cert_has_private_key_server_auth_eku_ca_flag_and_loopback_sans()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sim-tls-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var cert = TlsCertificateProvider.Resolve(new HostConfig(), dir);

            Assert.True(cert.HasPrivateKey);

            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
            Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), o => o.Value == "1.3.6.1.5.5.7.3.1"); // serverAuth

            var basic = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
            Assert.True(basic.CertificateAuthority);

            var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().Single();
            Assert.True(keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature));
            Assert.True(keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment));

            var san = cert.Extensions.Single(e => e.Oid?.Value == "2.5.29.17").Format(multiLine: false);
            Assert.Contains("localhost", san);
            Assert.Contains("127.0.0.1", san);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Old_minimal_cert_without_server_auth_is_regenerated()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sim-tls-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            // Simulate a previously-persisted minimal cert (no serverAuth EKU), like the original implementation produced.
            using (var rsa = System.Security.Cryptography.RSA.Create(2048))
            {
                var req = new CertificateRequest("CN=Intune Simulator", rsa,
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                using var minimal = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
                File.WriteAllBytes(Path.Combine(dir, "sim-cert.pfx"), minimal.Export(X509ContentType.Pfx, "sim"));
            }

            using var cert = TlsCertificateProvider.Resolve(new HostConfig(), dir);

            // The provider must have replaced it with a hardened cert carrying the serverAuth EKU.
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            Assert.NotNull(eku);
            Assert.Contains(eku!.EnhancedKeyUsages.Cast<Oid>(), o => o.Value == "1.3.6.1.5.5.7.3.1");
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }
}
