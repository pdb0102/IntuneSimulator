using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core.Recording;

/// <summary>Writes a concise one-line summary per request to the configured sink when enabled.</summary>
public sealed class RequestLogMiddleware
{
    private readonly RequestDelegate _next;
    public RequestLogMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx, SimulatorState state, RequestLogSink sink)
    {
        if (!state.LogRequests)
        {
            await _next(ctx);
            return;
        }

        long start = Environment.TickCount64;
        await _next(ctx);
        long elapsedMs = Environment.TickCount64 - start;

        string injected = ctx.Response.Headers.TryGetValue("X-Sim-Injected", out var inj)
            ? $"  [inject={inj}]"
            : "";

        sink.WriteLine($"{DateTime.Now:HH:mm:ss.fff}  {ctx.Request.Method,-6} {ctx.Request.Path}{ctx.Request.QueryString} -> {ctx.Response.StatusCode}  {elapsedMs}ms{injected}");
    }
}
