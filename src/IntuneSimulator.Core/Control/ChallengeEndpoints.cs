using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Control;

/// <summary>Maps the SCEP challenge-password endpoint that displays (GET) or returns (POST) the current challenge password.</summary>
public static class ChallengeEndpoints
{
    /// <summary>Maps the challenge-password endpoints onto the application.</summary>
    public static IEndpointRouteBuilder MapChallengeEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/challenge", (HttpContext ctx, SimulatorState state) =>
        {
            var html = $@"<html><body>
<h1>SCEP Challenge Password</h1>
<p>Copy this into your SCEP client / test:</p>
<pre id=""challenge"" style=""font-size:1.2em;background:#eee;padding:8px"">{System.Net.WebUtility.HtmlEncode(state.ChallengePassword)}</pre>
<p><a href=""/"">Configuration &amp; URLs</a> | <a href=""/control"">Behavior control</a></p>
</body></html>";
            return Results.Content(html, "text/html");
        });

        app.MapPost("/challenge", (HttpContext ctx, SimulatorState state) => SimResults.Json(ConfigInfo.Build(ctx, state)));

        return app;
    }
}
