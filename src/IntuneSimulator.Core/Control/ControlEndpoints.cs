using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace IntuneSimulator.Core.Control;

public static class ControlEndpoints
{
    private static readonly JsonSerializerOptions _indented = new() { WriteIndented = true };

    public static IEndpointRouteBuilder MapControlEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/control", (HttpContext ctx, SimulatorState state, IntuneSimulator.Core.Failure.FailureFlowEngine engine) =>
        {
            var json = JsonSerializer.Serialize(Settings(state, engine), _indented);
            var html = $@"<html><body>
<h1>Simulator Behavior Control</h1>
<p>POST JSON here to change settings. POST {{}} to read all. Current:</p>
<pre style=""background:#eee;padding:8px"">{System.Net.WebUtility.HtmlEncode(json)}</pre>
</body></html>";
            return Results.Content(html, "text/html");
        });

        app.MapPost("/control", async (HttpContext ctx, SimulatorState state, IntuneSimulator.Core.Failure.FailureFlowEngine engine) =>
        {
            using var reader = new StreamReader(ctx.Request.Body);
            var text = (await reader.ReadToEndAsync()).Trim();

            JsonDocument? doc = null;
            if (!string.IsNullOrEmpty(text) && text != "{}")
            {
                try { doc = JsonDocument.Parse(text); }
                catch (JsonException) { return SimResults.Json(new { error = "invalid_json", error_description = "Request body was not valid JSON." }, 400); }
            }

            using (doc)
            {
                if (doc is not null)
                {
                    var root = doc.RootElement;
                    if (root.TryGetProperty("authPassword", out var ap) && ap.ValueKind == JsonValueKind.String)
                        state.AuthPassword = ap.GetString()!;
                    if (root.TryGetProperty("challengePassword", out var cp) && cp.ValueKind == JsonValueKind.String)
                        state.ChallengePassword = cp.GetString()!;
                    if (root.TryGetProperty("cannedScepCode", out var sc))
                    {
                        if (sc.ValueKind == JsonValueKind.Null) state.CannedScepCode = null;
                        else if (sc.ValueKind == JsonValueKind.String) state.CannedScepCode = sc.GetString();
                        // non-string, non-null values are ignored (no crash)
                    }
                    if (root.TryGetProperty("enqueueRevocation", out var er) && er.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in er.EnumerateArray())
                        {
                            if (item.ValueKind != JsonValueKind.Object) continue;
                            state.EnqueueRevocation(new Revocation.RevocationRequestItem
                            {
                                RequestContext = item.TryGetProperty("requestContext", out var rcp) && rcp.ValueKind == JsonValueKind.String ? rcp.GetString()! : "",
                                SerialNumber = item.TryGetProperty("serialNumber", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString()! : "",
                                IssuerName = item.TryGetProperty("issuerName", out var i) && i.ValueKind == JsonValueKind.String ? i.GetString() : null,
                                CaConfiguration = item.TryGetProperty("caConfiguration", out var ca) && ca.ValueKind == JsonValueKind.String ? ca.GetString() : null,
                            });
                        }
                    }
                    if (root.TryGetProperty("logRequests", out var lr) && (lr.ValueKind == JsonValueKind.True || lr.ValueKind == JsonValueKind.False))
                        state.LogRequests = lr.GetBoolean();
                    if (root.TryGetProperty("failureFlow", out var ff) && ff.ValueKind == JsonValueKind.Object)
                    {
                        if (ff.TryGetProperty("mode", out var m) && m.ValueKind == JsonValueKind.String
                            && Enum.TryParse<IntuneSimulator.Core.Failure.FailureFlowMode>(m.GetString(), true, out var parsed))
                            engine.Mode = parsed;
                        if (ff.TryGetProperty("hardFaults", out var hf) && (hf.ValueKind == JsonValueKind.True || hf.ValueKind == JsonValueKind.False))
                            engine.HardFaults = hf.GetBoolean();
                        if (ff.TryGetProperty("action", out var act) && act.ValueKind == JsonValueKind.String)
                        {
                            switch (act.GetString()!.ToLowerInvariant())
                            {
                                case "advance": engine.Advance(); break;
                                case "reset": engine.Reset(); break;
                                case "setstep":
                                    if (ff.TryGetProperty("step", out var st) && st.ValueKind == JsonValueKind.Number) engine.SetStep(st.GetInt32());
                                    break;
                            }
                        }
                    }
                }
            }
            return SimResults.Json(Settings(state, engine));
        });

        app.MapPost("/control/failure/manual", (IntuneSimulator.Core.Failure.FailureFlowEngine engine) =>
        { engine.Mode = IntuneSimulator.Core.Failure.FailureFlowMode.Manual; engine.Reset(); return SimResults.Json(engine.Snapshot()); });
        app.MapPost("/control/failure/auto", (IntuneSimulator.Core.Failure.FailureFlowEngine engine) =>
        { engine.Mode = IntuneSimulator.Core.Failure.FailureFlowMode.Auto; engine.Reset(); return SimResults.Json(engine.Snapshot()); });

        app.MapGet("/control/requests", (IntuneSimulator.Core.Recording.RequestRecorder recorder) =>
            SimResults.Json(recorder.Snapshot().Select(r => new { endpoint = r.Endpoint, body = r.Body, at = r.At })));
        app.MapDelete("/control/requests", (IntuneSimulator.Core.Recording.RequestRecorder recorder) =>
        { recorder.Clear(); return SimResults.Json(new { cleared = true }); });

        return app;
    }

    internal static object Settings(SimulatorState state, IntuneSimulator.Core.Failure.FailureFlowEngine engine) => new
    {
        authPassword = state.AuthPassword,
        challengePassword = state.ChallengePassword,
        cannedScepCode = state.CannedScepCode,
        revocationQueueDepth = state.RevocationQueueCount,
        logRequests = state.LogRequests,
        failureFlow = engine.Snapshot(),
    };
}
