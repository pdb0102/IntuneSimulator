using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Signing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntuneSimulator.Tests;

public class GraphEndpointsTests
{
    private const string AppId = "0000000a-0000-0000-c000-000000000000";

    private static (SimulatorAppFactory f, HttpClient c) ClientWithToken()
    {
        var f = new SimulatorAppFactory();
        var c = f.CreateClient();
        var key = f.Services.GetRequiredService<TokenSigningKey>();
        var token = key.IssueAccessToken("iss", "https://graph.microsoft.com", "https://graph.microsoft.com/.default", TimeSpan.FromHours(1));
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (f, c);
    }

    [Fact]
    public async Task Msgraph_form_returns_both_services()
    {
        var (f, c) = ClientWithToken();
        using (f) using (c)
        {
            var doc = JsonDocument.Parse(await c.GetStringAsync($"/v1.0/servicePrincipals/appId={AppId}/endpoints"));
            var names = doc.RootElement.GetProperty("value").EnumerateArray()
                .Select(e => e.GetProperty("providerName").GetString()).ToList();
            Assert.Contains("ScepRequestValidationFEService", names);
            Assert.Contains("PkiConnectorFEService", names);
            foreach (var e in doc.RootElement.GetProperty("value").EnumerateArray())
                Assert.StartsWith("http://localhost", e.GetProperty("uri").GetString());
        }
    }

    [Fact]
    public async Task Aadgraph_form_returns_both_services()
    {
        var (f, c) = ClientWithToken();
        using (f) using (c)
        {
            var doc = JsonDocument.Parse(await c.GetStringAsync(
                $"/contoso.onmicrosoft.com/servicePrincipalsByAppId/{AppId}/serviceEndpoints?api-version=1.6"));
            Assert.Equal(2, doc.RootElement.GetProperty("value").GetArrayLength());
        }
    }

    [Fact]
    public async Task Missing_bearer_is_401()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.GetAsync($"/v1.0/servicePrincipals/appId={AppId}/endpoints");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Openid_config_route_still_works_after_graph_registered()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.GetAsync("/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("token_endpoint", out _));
    }
}
