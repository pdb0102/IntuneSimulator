using IntuneSimulator.Core.Signing;
using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core.Auth;

public static class BearerCheck
{
    /// <summary>Returns true if the request carries a bearer token the simulator itself issued (and it verifies).</summary>
    public static bool HasValidBearer(HttpContext ctx, TokenSigningKey key)
    {
        var header = ctx.Request.Headers.Authorization.ToString();
        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        // Audience is intentionally not checked: the simulator accepts any token it issued on any resource endpoint (the failure-flow matrix-walk reuses one token across all endpoints).
        return key.TryVerify(header[prefix.Length..].Trim(), out _);
    }
}
