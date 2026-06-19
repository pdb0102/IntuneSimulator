using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IntuneSimulator.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IntuneSimulator.Tests.E2E;

/// <summary>Runs the simulator on a real loopback HTTPS port with a self-signed cert, plus a client that trusts it.</summary>
public sealed class LoopbackServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    public string BaseUrl { get; }
    public X509Certificate2 Cert { get; }
    public IServiceProvider Services => _app.Services;

    private LoopbackServer(WebApplication app, string baseUrl, X509Certificate2 cert)
    { _app = app; BaseUrl = baseUrl; Cert = cert; }

    public static async Task<LoopbackServer> StartAsync(SimulatorOptions options)
    {
        var cert = CreateLoopbackCert();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddIntuneSimulator(options);
        builder.WebHost.ConfigureKestrel(k =>
            k.ListenAnyIP(0, lo => lo.UseHttps(cert))); // port 0 = dynamic
        var app = builder.Build();
        app.MapIntuneSimulator();
        await app.StartAsync();
        var addr = app.Urls.First();
        var port = new Uri(addr).Port;
        return new LoopbackServer(app, $"https://localhost:{port}", cert);
    }

    /// <summary>An HttpClient that trusts only this server's self-signed cert.</summary>
    public System.Net.Http.HttpClient CreateTrustingClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, c, _, errors) =>
                errors == System.Net.Security.SslPolicyErrors.None || c?.Thumbprint == Cert.Thumbprint
        };
        return new System.Net.Http.HttpClient(handler);
    }

    private static X509Certificate2 CreateLoopbackCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(System.Net.IPAddress.Loopback);
        req.CertificateExtensions.Add(san.Build());
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new X509Certificate2(cert.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
    }

    public async ValueTask DisposeAsync() { await _app.StopAsync(); await _app.DisposeAsync(); Cert.Dispose(); }
}
