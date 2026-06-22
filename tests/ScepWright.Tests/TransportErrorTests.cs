using ScepWright.Core.Transport;
using Xunit;

namespace ScepWright.Tests;

// A 404 alone tells a non-expert nothing; it almost always means the SCEP URL path is wrong.
public sealed class TransportErrorTests {
    [Fact]
    public void Http_404_message_hints_at_the_url_path() {
        string msg;

        msg = ScepHttpTransport.DescribeHttpError(404);
        Assert.Contains("404", msg);
        Assert.Contains("path", msg);
    }

    [Fact]
    public void Other_http_errors_stay_terse() {
        Assert.Equal("HTTP 500", ScepHttpTransport.DescribeHttpError(500));
    }
}
