using System.Security.Cryptography.X509Certificates;
using IntuneSimulator.Core;
using IntuneSimulator.Tests.E2E;
using Microsoft.Identity.Client;
using Microsoft.Intune; // sample classes
using Xunit;

namespace IntuneSimulator.Tests;

public class EndToEndMsalTests
{
    private const string Tenant = "contoso.onmicrosoft.com";
    private const string AppId = "11111111-2222-3333-4444-555555555555";

    private static IntuneScepValidator BuildValidator(LoopbackServer server, IConfidentialClientApplication app)
    {
        var tokenProvider = new MsalTokenProvider(app);
        var http = new Microsoft.Intune.HttpClient(server.CreateTrustingClient()); // sample IHttpClient wrapper
        var config = new Dictionary<string, string>
        {
            ["TENANT"] = Tenant,
            ["PROVIDER_NAME_AND_VERSION"] = "IntuneSimulator-E2E/1.0",
            ["INTUNE_RESOURCE_URL"] = server.BaseUrl + "/",
            ["MSAL_GRAPH_RESOURCE_URL"] = server.BaseUrl + "/",
            ["AAD_GRAPH_RESOURCE_URL"] = server.BaseUrl + "/",
            ["INTUNE_APP_ID"] = "0000000a-0000-0000-c000-000000000000",
        };
        var locationProvider = new IntuneServiceLocationProvider(config, tokenProvider, http);
        var intuneClient = new IntuneClient(config, tokenProvider, locationProvider, http);
        return new IntuneScepValidator(config, intuneClient: intuneClient);
    }

    // MSAL requires https authority; WithInstanceDiscovery(false) keeps MSAL talking only to the simulator
    // (no public AAD instance-discovery call). The /common/discovery/instance endpoint shape is covered by AadEndpointsTests.
    private static IConfidentialClientApplication SecretApp(LoopbackServer s) =>
        ConfidentialClientApplicationBuilder.Create(AppId)
            .WithClientSecret("IntunePassw0rd!")
            .WithAuthority($"{s.BaseUrl}/{Tenant}", validateAuthority: false)
            .WithInstanceDiscovery(false)
            .WithHttpClientFactory(new TrustingMsalHttpFactory(s.CreateTrustingClient()))
            .Build();

    private static IConfidentialClientApplication CertApp(LoopbackServer s, X509Certificate2 cert) =>
        ConfidentialClientApplicationBuilder.Create(AppId)
            .WithCertificate(cert)
            .WithAuthority($"{s.BaseUrl}/{Tenant}", validateAuthority: false)
            .WithInstanceDiscovery(false)
            .WithHttpClientFactory(new TrustingMsalHttpFactory(s.CreateTrustingClient()))
            .Build();

    [Fact]
    public async Task Secret_auth_full_validate_happy_path()
    {
        await using var server = await LoopbackServer.StartAsync(new SimulatorOptions { Tenant = Tenant, AuthPassword = "IntunePassw0rd!" });
        var validator = BuildValidator(server, SecretApp(server));
        await validator.ValidateRequestAsync(Guid.NewGuid().ToString(), "BASE64CSR"); // no throw == success
    }

    [Fact]
    public async Task Cert_auth_full_validate_happy_path()
    {
        using var clientCert = TestCerts.CreateSelfSigned("CN=client");
        var pfx = clientCert.Export(X509ContentType.Pfx, "pw");
        await using var server = await LoopbackServer.StartAsync(new SimulatorOptions
        {
            Tenant = Tenant,
            AuthPassword = "IntunePassw0rd!",
            AuthCertificatePfxBase64 = Convert.ToBase64String(pfx),
            AuthCertificatePassword = "pw",
        });
        var validator = BuildValidator(server, CertApp(server, clientCert));
        await validator.ValidateRequestAsync(Guid.NewGuid().ToString(), "BASE64CSR");
    }

    [Fact]
    public async Task Canned_scep_error_surfaces_as_exception()
    {
        await using var server = await LoopbackServer.StartAsync(new SimulatorOptions { Tenant = Tenant, AuthPassword = "IntunePassw0rd!" });
        ((SimulatorState)server.Services.GetService(typeof(SimulatorState))!).CannedScepCode = "SubjectNameMismatch";
        var validator = BuildValidator(server, SecretApp(server));
        var ex = await Assert.ThrowsAsync<IntuneScepServiceException>(() =>
            validator.ValidateRequestAsync(Guid.NewGuid().ToString(), "BASE64CSR"));
        Assert.Equal(IntuneScepServiceException.ErrorCode.SubjectNameMismatch, ex.ParsedErrorCode);
    }
}
