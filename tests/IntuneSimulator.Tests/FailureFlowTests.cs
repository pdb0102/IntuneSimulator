using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Failure;
using IntuneSimulator.Core.Signing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntuneSimulator.Tests;

public class FailureFlowTests
{
    [Fact]
    public async Task Walks_full_matrix_in_manual_mode()
    {
        using var f = new SimulatorAppFactory();
        var engine = f.Services.GetRequiredService<FailureFlowEngine>();
        engine.Mode = FailureFlowMode.Manual;
        var key = f.Services.GetRequiredService<TokenSigningKey>();
        var bearer = key.IssueAccessToken("iss", "aud", "scope", TimeSpan.FromHours(1));

        for (int step = 0; step < FailureChain.Matrix.Count; step++)
        {
            engine.SetStep(step);
            var expected = FailureChain.Matrix[step];
            using var c = f.CreateClient();
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            c.DefaultRequestHeaders.Add("api-version", "2018-02-20");

            var resp = await HitAsync(c, expected.EndpointId);

            Assert.Equal(expected.Mode.ToString(), resp.Headers.GetValues("X-Sim-Injected").Single());
            Assert.Equal(expected.Mode.SoftStatus(), (int)resp.StatusCode);
        }

        // Exhausted -> success at the scep-action endpoint (no injected header).
        engine.SetStep(FailureChain.Matrix.Count);
        using (var c = f.CreateClient())
        {
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            c.DefaultRequestHeaders.Add("api-version", "2018-02-20");
            var resp = await HitAsync(c, "scep-action");
            Assert.False(resp.Headers.Contains("X-Sim-Injected"));
            Assert.Equal(200, (int)resp.StatusCode);
        }
    }

    [Fact]
    public async Task Control_drives_failure_flow()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var r1 = await c.PostAsJsonAsync("/control", new { failureFlow = new { mode = "manual", action = "setStep", step = 5 } });
        var d1 = JsonDocument.Parse(await r1.Content.ReadAsStringAsync());
        Assert.Equal(5, d1.RootElement.GetProperty("failureFlow").GetProperty("stepIndex").GetInt32());

        await c.PostAsJsonAsync("/control", new { failureFlow = new { action = "advance" } });
        var r3 = await c.PostAsync("/control", new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        var d3 = JsonDocument.Parse(await r3.Content.ReadAsStringAsync());
        Assert.Equal(6, d3.RootElement.GetProperty("failureFlow").GetProperty("stepIndex").GetInt32());

        await c.PostAsJsonAsync("/control", new { failureFlow = new { action = "reset" } });
        var r4 = await c.PostAsync("/control", new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        var d4 = JsonDocument.Parse(await r4.Content.ReadAsStringAsync());
        Assert.Equal(0, d4.RootElement.GetProperty("failureFlow").GetProperty("stepIndex").GetInt32());
    }

    [Fact]
    public async Task Failure_manual_convenience_route_resets_to_step_zero()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        // Move the cursor away from 0 first.
        await c.PostAsJsonAsync("/control", new { failureFlow = new { mode = "manual", action = "setStep", step = 7 } });
        // The convenience route should enable manual AND reset to step 0.
        var resp = await c.PostAsync("/control/failure/manual", new StringContent("", System.Text.Encoding.UTF8, "application/json"));
        var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("Manual", doc.RootElement.GetProperty("mode").GetString());
        Assert.Equal(0, doc.RootElement.GetProperty("stepIndex").GetInt32());
    }

    /// <summary>Issues the right HTTP request to reach a given chain endpoint.</summary>
    private static async Task<HttpResponseMessage> HitAsync(HttpClient c, string endpointId) => endpointId switch
    {
        "instance-discovery" => await c.GetAsync("/common/discovery/instance?api-version=1.1"),
        "openid-config" => await c.GetAsync("/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration"),
        "token-graph" => await c.PostAsync("/contoso.onmicrosoft.com/oauth2/v2.0/token",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["scope"] = "https://graph.microsoft.com/.default", ["client_id"] = "a", ["client_secret"] = "IntunePassw0rd!", ["grant_type"] = "client_credentials" })),
        "graph-discovery" => await c.GetAsync("/v1.0/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints"),
        "token-intune" => await c.PostAsync("/contoso.onmicrosoft.com/oauth2/v2.0/token",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["scope"] = "https://api.manage.microsoft.com//.default", ["client_id"] = "a", ["client_secret"] = "IntunePassw0rd!", ["grant_type"] = "client_credentials" })),
        "scep-action" => await c.PostAsJsonAsync("/ScepActions/validateRequest", new { request = new { transactionId = "t" } }),
        _ => throw new ArgumentException(endpointId),
    };
}
