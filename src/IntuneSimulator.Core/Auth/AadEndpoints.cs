using IntuneSimulator.Core.Signing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Auth;

public static class AadEndpoints
{
    public static IEndpointRouteBuilder MapAadEndpoints(this IEndpointRouteBuilder app)
    {
        // Instance discovery (MSAL authority validation).
        app.MapGet("/common/discovery/instance", (HttpContext ctx) =>
        {
            var host = new Uri(ctx.BaseUrl()).Host;
            return SimResults.Json(new
            {
                tenant_discovery_endpoint = $"{ctx.BaseUrl()}/common/v2.0/.well-known/openid-configuration",
                api_version = "1.1",
                metadata = new[]
                {
                    new { preferred_network = host, preferred_cache = host, aliases = new[] { host } }
                }
            });
        });

        // OIDC metadata for any tenant segment (incl. "common").
        app.MapGet("/{tenant}/v2.0/.well-known/openid-configuration", (HttpContext ctx, string tenant) =>
            OpenIdConfig(ctx, tenant));
        app.MapGet("/{tenant}/.well-known/openid-configuration", (HttpContext ctx, string tenant) =>
            OpenIdConfig(ctx, tenant));

        // JWKS.
        app.MapGet("/{tenant}/discovery/v2.0/keys", (HttpContext ctx, TokenSigningKey key) =>
            Results.Content(key.GetJwksJson(), "application/json"));

        // Token endpoint (client-credentials).
        app.MapPost("/{tenant}/oauth2/v2.0/token", async (HttpContext ctx, string tenant,
            SimulatorState state, ClientCredentialValidator validator, TokenSigningKey key) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            if (form["grant_type"].ToString() != "client_credentials")
                return SimResults.Json(new { error = "unsupported_grant_type", error_description = "Only client_credentials is supported." }, 400);
            string clientId = form["client_id"].ToString();
            string scope = form["scope"].ToString();
            string tokenEndpoint = $"{ctx.BaseUrl()}/{tenant}/oauth2/v2.0/token";

            bool ok;
            string reason;
            if (!string.IsNullOrEmpty(form["client_assertion"]))
                ok = validator.ValidateClientAssertion(state, clientId, form["client_assertion"], tokenEndpoint, out reason);
            else
                ok = validator.ValidateSecret(state, clientId, form["client_secret"], out reason);

            if (!ok)
                return SimResults.Json(new { error = "invalid_client", error_description = reason }, 400);

            // Audience = scope without the trailing "/.default".
            string audience = scope.EndsWith("/.default", StringComparison.OrdinalIgnoreCase)
                ? scope[..^"/.default".Length]
                : scope;
            var token = key.IssueAccessToken(
                issuer: $"{ctx.BaseUrl()}/{tenant}/v2.0",
                audience: audience,
                scope: scope,
                lifetime: TimeSpan.FromHours(1),
                appId: string.IsNullOrEmpty(clientId) ? "intune-simulator" : clientId);

            return SimResults.Json(new
            {
                token_type = "Bearer",
                expires_in = 3599,
                ext_expires_in = 3599,
                access_token = token
            });
        });

        return app;
    }

    private static IResult OpenIdConfig(HttpContext ctx, string tenant)
    {
        var b = ctx.BaseUrl();
        return SimResults.Json(new
        {
            issuer = $"{b}/{tenant}/v2.0",
            authorization_endpoint = $"{b}/{tenant}/oauth2/v2.0/authorize",
            token_endpoint = $"{b}/{tenant}/oauth2/v2.0/token",
            jwks_uri = $"{b}/{tenant}/discovery/v2.0/keys",
            response_modes_supported = new[] { "query", "fragment", "form_post" },
            response_types_supported = new[] { "code", "id_token", "token" },
            grant_types_supported = new[] { "client_credentials", "authorization_code" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "private_key_jwt" },
            subject_types_supported = new[] { "pairwise" },
            id_token_signing_alg_values_supported = new[] { "RS256" }
        });
    }
}
