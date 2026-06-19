using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Revocation;
using IntuneSimulator.Core.Signing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntuneSimulator.Tests;

public class RevocationEndpointsTests
{
    private static HttpClient Pki(SimulatorAppFactory f)
    {
        var c = f.CreateClient();
        var key = f.Services.GetRequiredService<TokenSigningKey>();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            key.IssueAccessToken("iss", "https://api.manage.microsoft.com", "scope", TimeSpan.FromHours(1)));
        c.DefaultRequestHeaders.Add("api-version", "5019-05-05");
        return c;
    }

    [Fact]
    public async Task Download_returns_queued_items()
    {
        using var f = new SimulatorAppFactory();
        f.Services.GetRequiredService<SimulatorState>()
            .EnqueueRevocation(new RevocationRequestItem { RequestContext = "ctx1", SerialNumber = "AA" });
        using var c = Pki(f);
        var resp = await c.PostAsJsonAsync("/CertificateAuthorityRequests/downloadRevocationRequests",
            new { downloadParameters = new { maxRequests = 50 } });
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("ctx1", doc.RootElement.GetProperty("value")[0].GetProperty("requestContext").GetString());
    }

    [Fact]
    public async Task Upload_returns_value_true()
    {
        using var f = new SimulatorAppFactory();
        using var c = Pki(f);
        var resp = await c.PostAsJsonAsync("/CertificateAuthorityRequests/uploadRevocationResults",
            new { results = new[] { new { requestContext = "ctx1", succeeded = true } } });
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("value").GetBoolean());
    }

    [Fact]
    public async Task Disabled_revocation_returns_404()
    {
        using var f = new SimulatorAppFactory(new SimulatorOptions { RevocationEnabled = false });
        using var c = Pki(f);
        var resp = await c.PostAsJsonAsync("/CertificateAuthorityRequests/downloadRevocationRequests",
            new { downloadParameters = new { maxRequests = 50 } });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Download_filters_by_issuer_name()
    {
        using var f = new SimulatorAppFactory();
        var state = f.Services.GetRequiredService<SimulatorState>();
        state.EnqueueRevocation(new RevocationRequestItem { RequestContext = "a", SerialNumber = "1", IssuerName = "CA-X" });
        state.EnqueueRevocation(new RevocationRequestItem { RequestContext = "b", SerialNumber = "2", IssuerName = "CA-Y" });
        using var c = Pki(f);
        var resp = await c.PostAsJsonAsync("/CertificateAuthorityRequests/downloadRevocationRequests",
            new { downloadParameters = new { maxRequests = 50, issuerName = "CA-Y" } });
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var arr = doc.RootElement.GetProperty("value");
        Assert.Equal(1, arr.GetArrayLength());
        Assert.Equal("b", arr[0].GetProperty("requestContext").GetString());
    }
}
