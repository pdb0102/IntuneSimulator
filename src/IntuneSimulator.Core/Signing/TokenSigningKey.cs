using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace IntuneSimulator.Core.Signing;

/// <summary>RSA key used to sign and verify the simulator's own access tokens, and to publish a JWKS.</summary>
public sealed class TokenSigningKey : IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _securityKey;
    private readonly SigningCredentials _signing;
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };

    /// <summary>Generates a fresh 2048-bit RSA signing key with a random key id.</summary>
    public TokenSigningKey()
    {
        _rsa = RSA.Create(2048);
        _securityKey = new RsaSecurityKey(_rsa) { KeyId = Guid.NewGuid().ToString("N") };
        _signing = new SigningCredentials(_securityKey, SecurityAlgorithms.RsaSha256);
    }

    /// <summary>Gets the key id (kid) published in the JWKS and token headers.</summary>
    public string KeyId => _securityKey.KeyId;

    /// <summary>Issues a signed JWT access token with the given issuer, audience, scope, and lifetime.</summary>
    public string IssueAccessToken(string issuer, string audience, string scope, TimeSpan lifetime, string appId = "intune-simulator")
    {
        var now = DateTime.UtcNow;
        var expires = now.Add(lifetime);
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[]
            {
                new Claim("scope", scope),
                new Claim("appid", appId),
                new Claim("ver", "2.0"),
            },
            notBefore: expires > now ? now : null,
            expires: expires,
            signingCredentials: _signing);
        return _handler.WriteToken(token);
    }

    /// <summary>Validates a token against this signing key and returns the resulting principal.</summary>
    /// <returns>True if the token is well-formed, unexpired, and signed by this key.</returns>
    public bool TryVerify(string token, out ClaimsPrincipal? principal)
    {
        principal = null;
        if (string.IsNullOrWhiteSpace(token)) return false;
        try
        {
            principal = _handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                IssuerSigningKey = _securityKey,
                ValidateIssuerSigningKey = true,
            }, out _);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Releases the underlying RSA key.</summary>
    public void Dispose() => _rsa.Dispose();

    /// <summary>JWKS document for the OIDC <c>jwks_uri</c>.</summary>
    public string GetJwksJson()
    {
        var p = _rsa.ExportParameters(false);
        var jwk = new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = KeyId,
                    alg = "RS256",
                    n = Base64UrlEncoder.Encode(p.Modulus),
                    e = Base64UrlEncoder.Encode(p.Exponent),
                }
            }
        };
        return JsonSerializer.Serialize(jwk);
    }
}
