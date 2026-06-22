using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Signing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntuneSimulator.Tests;

public class ScepEndpointsTests
{
    private static HttpClient IntuneClient(SimulatorAppFactory f)
    {
        var c = f.CreateClient();
        var key = f.Services.GetRequiredService<TokenSigningKey>();
        var token = key.IssueAccessToken("iss", "https://api.manage.microsoft.com", "scope", TimeSpan.FromHours(1));
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        c.DefaultRequestHeaders.Add("api-version", "2018-02-20");
        return c;
    }

    [Fact]
    public async Task Validate_returns_success_by_default()
    {
        using var f = new SimulatorAppFactory();
        using var c = IntuneClient(f);
        var resp = await c.PostAsJsonAsync("/ScepActions/validateRequest", new
        {
            request = new { transactionId = "t1", certificateRequest = "BASE64CSR", callerInfo = "prov/1.0" }
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("Success", doc.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Validate_returns_canned_code_when_set()
    {
        using var f = new SimulatorAppFactory();
        f.Services.GetRequiredService<SimulatorState>().CannedScepCode = "ChallengePasswordMissing";
        using var c = IntuneClient(f);
        var resp = await c.PostAsJsonAsync("/ScepActions/validateRequest", new { request = new { transactionId = "t1" } });
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("ChallengePasswordMissing", doc.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Success_notification_records_request()
    {
        using var f = new SimulatorAppFactory();
        using var c = IntuneClient(f);
        await c.PostAsJsonAsync("/ScepActions/successNotification", new
        {
            notification = new { transactionId = "t9", certificateThumbprint = "ABC" }
        });
        var rec = f.Services.GetRequiredService<IntuneSimulator.Core.Recording.RequestRecorder>().Snapshot();
        Assert.Contains(rec, r => r.Endpoint == "ScepActions/successNotification" && r.Body.Contains("t9"));
    }

    [Fact]
    public async Task Missing_bearer_is_401()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        c.DefaultRequestHeaders.Add("api-version", "2018-02-20");
        var resp = await c.PostAsJsonAsync("/ScepActions/validateRequest", new { request = new { transactionId = "t" } });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Control_requests_endpoint_exposes_and_clears_recordings()
    {
        using var f = new SimulatorAppFactory();
        using var c = IntuneClient(f); // bearer + api-version helper already in this class
        await c.PostAsJsonAsync("/ScepActions/validateRequest", new { request = new { transactionId = "tRec" } });

        using var plain = f.CreateClient();
        var listed = await plain.GetStringAsync("/control/requests");
        Assert.Contains("tRec", listed);
        Assert.Contains("ScepActions/validateRequest", listed);

        var del = await plain.DeleteAsync("/control/requests");
        Assert.Equal(System.Net.HttpStatusCode.OK, del.StatusCode);
        var after = await plain.GetStringAsync("/control/requests");
        Assert.DoesNotContain("tRec", after);
    }
}
