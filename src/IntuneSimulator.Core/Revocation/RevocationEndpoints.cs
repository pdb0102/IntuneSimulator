using IntuneSimulator.Core.Auth;
using IntuneSimulator.Core.Recording;
using IntuneSimulator.Core.Signing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Revocation;

public static class RevocationEndpoints
{
    public static IEndpointRouteBuilder MapRevocationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/CertificateAuthorityRequests/downloadRevocationRequests",
            async (HttpContext ctx, TokenSigningKey key, SimulatorState state, RequestRecorder rec) =>
        {
            if (!BearerCheck.HasValidBearer(ctx, key)) return Results.Unauthorized();
            var body = await ctx.Request.ReadFromJsonAsync<DownloadBody>();
            rec.Record("CertificateAuthorityRequests/downloadRevocationRequests", "download");
            int max = body?.DownloadParameters?.MaxRequests ?? 50;
            var items = state.DequeueRevocations(max, body?.DownloadParameters?.IssuerName);
            return SimResults.Json(new { value = items });
        });

        app.MapPost("/CertificateAuthorityRequests/uploadRevocationResults",
            async (HttpContext ctx, TokenSigningKey key, RequestRecorder rec) =>
        {
            if (!BearerCheck.HasValidBearer(ctx, key)) return Results.Unauthorized();
            var body = await ctx.Request.ReadFromJsonAsync<UploadBody>();
            rec.Record("CertificateAuthorityRequests/uploadRevocationResults",
                $"{body?.Results.Count ?? 0} results");
            return SimResults.Json(new { value = true });
        });

        return app;
    }
}
