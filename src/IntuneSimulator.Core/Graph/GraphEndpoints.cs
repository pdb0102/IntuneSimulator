using IntuneSimulator.Core.Auth;
using IntuneSimulator.Core.Signing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Graph;

public static class GraphEndpoints
{
    public const string ScepService = "ScepRequestValidationFEService";
    public const string PkiService = "PkiConnectorFEService";

    public static IEndpointRouteBuilder MapGraphEndpoints(this IEndpointRouteBuilder app)
    {
        // MS Graph form: /v1.0/servicePrincipals/appId={appId}/endpoints
        // The segment "appId={appId}" contains a literal prefix; ASP.NET Core minimal routing
        // supports mixed literal+parameter segments, so this template should bind correctly.
        app.MapGet("/v{version}/servicePrincipals/appId={appId}/endpoints",
            (HttpContext ctx, TokenSigningKey key, string version, string appId) =>
                BearerCheck.HasValidBearer(ctx, key) ? Discovery(ctx) : Results.Unauthorized());

        // AAD Graph form: /{tenant}/servicePrincipalsByAppId/{appId}/serviceEndpoints
        app.MapGet("/{tenant}/servicePrincipalsByAppId/{appId}/serviceEndpoints",
            (HttpContext ctx, TokenSigningKey key, string tenant, string appId) =>
                BearerCheck.HasValidBearer(ctx, key) ? Discovery(ctx) : Results.Unauthorized());

        return app;
    }

    private static IResult Discovery(HttpContext ctx)
    {
        var b = ctx.BaseUrl();
        return SimResults.Json(new
        {
            value = new[]
            {
                new { providerName = ScepService, serviceName = ScepService, uri = b },
                new { providerName = PkiService,  serviceName = PkiService,  uri = b },
            }
        });
    }
}
