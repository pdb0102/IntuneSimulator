using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core.Failure;

public sealed class FailureFlowMiddleware
{
    private readonly RequestDelegate _next;
    public FailureFlowMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx, FailureFlowEngine engine, SimulatorState state)
    {
        if (engine.Mode == FailureFlowMode.Off) { await _next(ctx); return; }

        var endpointId = await FailureChain.IdentifyAsync(ctx);
        if (endpointId is null) { await _next(ctx); return; }

        var mode = engine.ResolveInjection(endpointId);
        if (mode is null) { await _next(ctx); return; }

        await InjectAsync(ctx, mode.Value, engine, state);
    }

    private static async Task InjectAsync(HttpContext ctx, FailureMode mode, FailureFlowEngine engine, SimulatorState state)
    {
        ctx.Response.Headers["X-Sim-Injected"] = mode.ToString();

        switch (mode)
        {
            case FailureMode.Timeout:
                if (engine.HardFaults)
                {
                    try { await Task.Delay(engine.TimeoutDelayMs, ctx.RequestAborted); } catch { /* client gave up */ }
                    ctx.Abort();
                    return;
                }
                ctx.Response.StatusCode = 504;
                await ctx.Response.WriteAsync("simulated timeout");
                return;

            case FailureMode.ConnectionRefused:
                if (engine.HardFaults) { ctx.Abort(); return; }
                ctx.Response.StatusCode = 502;
                await ctx.Response.WriteAsync("simulated connection failure");
                return;

            case FailureMode.Http500:
            case FailureMode.Http503:
            case FailureMode.Http401:
                ctx.Response.StatusCode = mode.SoftStatus();
                await ctx.Response.WriteAsync($"simulated {mode}");
                return;

            case FailureMode.InvalidClient400:
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{\"error\":\"invalid_client\",\"error_description\":\"simulated\"}");
                return;

            case FailureMode.MalformedJson:
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("{ \"code\": \"Succ");  // truncated, unparseable
                return;

            case FailureMode.ScepError:
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/json";
                var code = string.IsNullOrEmpty(state.CannedScepCode) ? "SignatureValidationFailed" : state.CannedScepCode;
                await ctx.Response.WriteAsync($"{{\"code\":\"{code}\",\"errorDescription\":\"simulated SCEP error\"}}");
                return;
        }
    }
}
