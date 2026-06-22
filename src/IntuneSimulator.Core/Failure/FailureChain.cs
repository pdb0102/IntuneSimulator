using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core.Failure;

/// <summary>One step of the failure matrix: a 0-based index, the endpoint it targets, and the failure to inject there.</summary>
/// <param name="Index">The 0-based position of this step in the matrix.</param>
/// <param name="EndpointId">The chain endpoint id this step targets.</param>
/// <param name="EndpointTitle">A human-readable title for the targeted endpoint.</param>
/// <param name="Mode">The failure mode injected at this step.</param>
public sealed record FailureStep(int Index, string EndpointId, string EndpointTitle, FailureMode Mode);

/// <summary>The ordered chain of endpoints in one full verification and the failure modes walked at each.</summary>
public static class FailureChain
{
    private sealed record Endpoint(string Id, string Title, FailureMode[] Modes);

    private static readonly Endpoint[] Endpoints =
    {
        new("instance-discovery", "AAD instance discovery",
            new[] { FailureMode.Timeout, FailureMode.ConnectionRefused, FailureMode.Http500, FailureMode.Http503, FailureMode.MalformedJson }),
        new("openid-config", "AAD OpenID configuration",
            new[] { FailureMode.Timeout, FailureMode.Http500, FailureMode.Http503, FailureMode.MalformedJson }),
        new("token-graph", "Token (MS Graph scope)",
            new[] { FailureMode.Timeout, FailureMode.ConnectionRefused, FailureMode.Http500, FailureMode.Http503, FailureMode.InvalidClient400, FailureMode.MalformedJson }),
        new("graph-discovery", "Graph service discovery",
            new[] { FailureMode.Timeout, FailureMode.Http500, FailureMode.Http503, FailureMode.Http401, FailureMode.MalformedJson }),
        new("token-intune", "Token (Intune scope)",
            new[] { FailureMode.Timeout, FailureMode.Http500, FailureMode.Http503, FailureMode.InvalidClient400, FailureMode.MalformedJson }),
        new("scep-action", "Intune SCEP action",
            new[] { FailureMode.Timeout, FailureMode.ConnectionRefused, FailureMode.Http500, FailureMode.Http503, FailureMode.Http401, FailureMode.MalformedJson, FailureMode.ScepError }),
    };

    /// <summary>The full, ordered failure matrix: every (endpoint, failure mode) pair walked during a verification.</summary>
    public static readonly IReadOnlyList<FailureStep> Matrix = BuildMatrix();
    /// <summary>Gets the id of the first endpoint in the chain (used to detect the start of a new verification).</summary>
    public static string FirstEndpointId => Endpoints[0].Id;

    private static FailureStep[] BuildMatrix()
    {
        var list = new List<FailureStep>();
        int i = 0;
        foreach (var e in Endpoints)
            foreach (var m in e.Modes)
                list.Add(new FailureStep(i++, e.Id, e.Title, m));
        return list.ToArray();
    }

    /// <summary>Classifies an incoming request to a chain endpoint id, or null if it is not part of the chain.</summary>
    public static async Task<string?> IdentifyAsync(HttpContext ctx)
    {
        var path = ctx.Request.Path.Value ?? "";
        var method = ctx.Request.Method;

        if (method == "GET" && path == "/common/discovery/instance") return "instance-discovery";
        if (method == "GET" && path.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)) return "openid-config";
        if (method == "GET" && (path.Contains("/servicePrincipals/appId=", StringComparison.OrdinalIgnoreCase)
                                || path.Contains("/servicePrincipalsByAppId/", StringComparison.OrdinalIgnoreCase))) return "graph-discovery";
        if (method == "POST" && path.StartsWith("/ScepActions/", StringComparison.OrdinalIgnoreCase)) return "scep-action";

        if (method == "POST" && path.EndsWith("/oauth2/v2.0/token", StringComparison.OrdinalIgnoreCase))
        {
            string scope = "";
            if (ctx.Request.HasFormContentType)
            {
                var form = await ctx.Request.ReadFormAsync(); // cached for downstream handlers
                scope = form["scope"].ToString();
            }
            return scope.Contains("graph", StringComparison.OrdinalIgnoreCase) ? "token-graph" : "token-intune";
        }
        return null;
    }
}
