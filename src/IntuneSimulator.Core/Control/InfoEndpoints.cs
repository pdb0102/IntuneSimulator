using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Control;

/// <summary>Maps the root info page that lists the URLs and values needed to point a product at this simulator.</summary>
public static class InfoEndpoints
{
    private static readonly JsonSerializerOptions _indented = new() { WriteIndented = true };

    /// <summary>Maps the info-page endpoint onto the application.</summary>
    public static IEndpointRouteBuilder MapInfoEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/", (HttpContext ctx, SimulatorState state) =>
        {
            var info = ConfigInfo.Build(ctx, state);
            var json = JsonSerializer.Serialize(info, _indented);
            var html = $@"<html><body>
<h1>Intune Simulator</h1>
<p>Configure your product with these URLs (AuthUrl MUST be the https one — MSAL requires https):</p>
<pre style=""background:#eee;padding:8px"">{System.Net.WebUtility.HtmlEncode(json)}</pre>
<p><a href=""/challenge"">Challenge password</a> | <a href=""/control"">Behavior control</a></p>
</body></html>";
            return Results.Content(html, "text/html");
        });
        return app;
    }

    /// <summary>Builds the plain-text startup banner (also used by the Host console output).</summary>
    public static string BuildBanner(string baseUrl, SimulatorState state) =>
        $"""
        ================ Intune Simulator ================
        Base URL (advertised) : {baseUrl}
        AuthUrl  (https!)     : {baseUrl}/
        MsGraphUrl            : {baseUrl}/
        GraphUrl (AAD)        : {baseUrl}/
        IntuneResourceUrl     : {baseUrl}/
        Tenant                : {state.Options.Tenant}
        AppId                 : {state.Options.AppId}
        Auth password         : {state.AuthPassword}
        Challenge password    : {state.ChallengePassword}
        Info page             : {baseUrl}/
        Challenge endpoint    : {baseUrl}/challenge
        Control endpoint      : {baseUrl}/control
        ==================================================
        """;
}
