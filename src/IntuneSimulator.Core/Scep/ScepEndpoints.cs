using IntuneSimulator.Core.Auth;
using IntuneSimulator.Core.Recording;
using IntuneSimulator.Core.Signing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Scep;

public static class ScepEndpoints
{
    public static IEndpointRouteBuilder MapScepEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ScepActions/validateRequest", Handle("ScepActions/validateRequest", applyCannedCode: true));
        app.MapPost("/ScepActions/successNotification", Handle("ScepActions/successNotification", applyCannedCode: false));
        app.MapPost("/ScepActions/failureNotification", Handle("ScepActions/failureNotification", applyCannedCode: false));
        return app;
    }

    // The `api-version` header is accepted but intentionally not strictly validated — a test double accepts any version.
    private static Func<HttpContext, TokenSigningKey, SimulatorState, RequestRecorder, Task<IResult>> Handle(
        string endpoint, bool applyCannedCode)
    {
        return async (ctx, key, state, recorder) =>
        {
            if (!BearerCheck.HasValidBearer(ctx, key)) return Results.Unauthorized();

            ctx.Request.EnableBuffering();
            using var reader = new StreamReader(ctx.Request.Body, leaveOpen: true);
            string body = await reader.ReadToEndAsync();
            ctx.Request.Body.Position = 0;
            recorder.Record(endpoint, body);

            var result = new ScepResult();
            if (applyCannedCode && !string.IsNullOrEmpty(state.CannedScepCode))
            {
                result.Code = state.CannedScepCode!;
                result.ErrorDescription = $"Simulated error: {state.CannedScepCode}";
            }
            return SimResults.Json(result); // always HTTP 200, like real Intune
        };
    }
}
