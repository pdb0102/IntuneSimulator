using System.Net.Http.Json;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Recording;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IntuneSimulator.Tests;

public class RequestLogTests
{
    [Fact]
    public async Task Logs_a_line_per_request_when_enabled()
    {
        using var f = new SimulatorAppFactory(new SimulatorOptions { LogRequests = true });
        var sw = new StringWriter();
        f.Services.GetRequiredService<RequestLogSink>().Writer = sw;
        using var c = f.CreateClient();

        await c.GetAsync("/challenge");

        var output = sw.ToString();
        Assert.Contains("GET", output);
        Assert.Contains("/challenge", output);
        Assert.Contains("-> 200", output);
    }

    [Fact]
    public async Task Does_not_log_when_disabled()
    {
        using var f = new SimulatorAppFactory(new SimulatorOptions { LogRequests = false });
        var sw = new StringWriter();
        f.Services.GetRequiredService<RequestLogSink>().Writer = sw;
        using var c = f.CreateClient();

        await c.GetAsync("/challenge");

        Assert.Equal("", sw.ToString());
    }

    [Fact]
    public async Task Control_can_toggle_request_logging()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsJsonAsync("/control", new { logRequests = true });
        var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("logRequests").GetBoolean());
        Assert.True(f.Services.GetRequiredService<SimulatorState>().LogRequests);
    }
}
