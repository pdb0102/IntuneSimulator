using System.Net;
using Xunit;

namespace IntuneSimulator.Tests;

public class BootTests
{
    [Fact]
    public async Task Root_returns_200_html()
    {
        using var factory = new SimulatorAppFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
    }
}
