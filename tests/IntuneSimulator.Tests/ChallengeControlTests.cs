using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using IntuneSimulator.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntuneSimulator.Tests;

public class ChallengeControlTests
{
    [Fact]
    public async Task Challenge_get_shows_password_html()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var pw = f.Services.GetRequiredService<SimulatorState>().ChallengePassword;
        var html = await c.GetStringAsync("/challenge");
        Assert.Contains(pw, html);
    }

    [Fact]
    public async Task Challenge_post_empty_returns_json()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync("/challenge", new StringContent("", Encoding.UTF8, "application/json"));
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(doc.RootElement.GetProperty("challengePassword").GetString()));
        Assert.Contains("authUrl", doc.RootElement.GetProperty("urls").ToString());
    }

    [Fact]
    public async Task Control_post_empty_returns_all_settings()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync("/control", new StringContent("{}", Encoding.UTF8, "application/json"));
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("IntunePassw0rd!", doc.RootElement.GetProperty("authPassword").GetString());
    }

    [Fact]
    public async Task Control_post_sets_values()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/control", new { authPassword = "changed!", cannedScepCode = "ChallengeExpired" });
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("changed!", doc.RootElement.GetProperty("authPassword").GetString());
        Assert.Equal("ChallengeExpired", doc.RootElement.GetProperty("cannedScepCode").GetString());
        Assert.Equal("changed!", f.Services.GetRequiredService<SimulatorState>().AuthPassword);
    }

    [Fact]
    public async Task Info_page_lists_urls()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var html = await c.GetStringAsync("/");
        Assert.Contains("authUrl", html);
    }

    [Fact]
    public async Task Control_malformed_json_returns_400()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync("/control", new StringContent("{\"authPassword\":", Encoding.UTF8, "application/json"));
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Control_non_string_field_does_not_crash()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync("/control", new StringContent("{\"cannedScepCode\":123}", Encoding.UTF8, "application/json"));
        Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Control_enqueue_revocation_increments_depth()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/control", new { enqueueRevocation = new[] { new { requestContext = "ctxA", serialNumber = "AA", caConfiguration = "cfg1" } } });
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(1, doc.RootElement.GetProperty("revocationQueueDepth").GetInt32());
    }
}
