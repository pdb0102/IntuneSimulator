using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace IntuneSimulator.Core.Auth;

/// <summary>Validates client-credentials grant material against the configured secret or certificate.</summary>
public sealed class ClientCredentialValidator
{
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };

    /// <summary>Validates a client_secret against the configured auth password.</summary>
    /// <param name="reason">On failure, a human-readable explanation; empty on success.</param>
    /// <returns>True if the secret matches.</returns>
    public bool ValidateSecret(SimulatorState state, string clientId, string? clientSecret, out string reason)
    {
        if (string.IsNullOrEmpty(clientSecret))
        {
            reason = "client_secret missing";
            return false;
        }
        if (!string.Equals(clientSecret, state.AuthPassword, StringComparison.Ordinal))
        {
            reason = "client_secret does not match configured auth password";
            return false;
        }
        reason = "";
        return true;
    }

    /// <summary>Validates a client_assertion JWT signed by the configured auth certificate.</summary>
    /// <param name="reason">On failure, a human-readable explanation; empty on success.</param>
    /// <returns>True if the assertion is valid and its subject matches the client id.</returns>
    public bool ValidateClientAssertion(SimulatorState state, string clientId, string? assertion, string tokenEndpoint, out string reason)
    {
        var cert = state.AuthCertificate;
        if (cert is null)
        {
            reason = "certificate auth attempted but no auth certificate configured";
            return false;
        }
        if (string.IsNullOrEmpty(assertion))
        {
            reason = "client_assertion missing";
            return false;
        }
        try
        {
            var principal = _handler.ValidateToken(assertion, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = clientId,
                ValidateAudience = true,
                ValidAudiences = AudienceVariants(tokenEndpoint),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                IssuerSigningKey = new X509SecurityKey(cert),
                ValidateIssuerSigningKey = true,
            }, out _);

            var sub = principal.FindFirst("sub")?.Value;
            if (!string.Equals(sub, clientId, StringComparison.Ordinal))
            {
                reason = "client_assertion sub claim does not match client_id";
                return false;
            }

            reason = "";
            return true;
        }
        catch (Exception ex)
        {
            reason = "client_assertion validation failed: " + ex.Message;
            return false;
        }
    }

    /// <summary>Accept the token endpoint with and without a trailing slash (AAD tolerates both).</summary>
    private static string[] AudienceVariants(string tokenEndpoint)
    {
        var trimmed = tokenEndpoint.TrimEnd('/');
        return trimmed == tokenEndpoint
            ? new[] { tokenEndpoint, tokenEndpoint + "/" }
            : new[] { tokenEndpoint, trimmed };
    }
}
