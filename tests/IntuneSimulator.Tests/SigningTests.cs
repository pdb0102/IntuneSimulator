using IntuneSimulator.Core.Signing;
using Xunit;

namespace IntuneSimulator.Tests;

public class SigningTests
{
    [Fact]
    public void Issued_token_verifies_and_carries_claims()
    {
        using var key = new TokenSigningKey();
        var token = key.IssueAccessToken(
            issuer: "https://sim/contoso.onmicrosoft.com/v2.0",
            audience: "https://api.manage.microsoft.com",
            scope: "https://api.manage.microsoft.com//.default",
            lifetime: TimeSpan.FromHours(1));

        Assert.True(key.TryVerify(token, out var claims));
        Assert.Equal("https://api.manage.microsoft.com", claims!.FindFirst("aud")?.Value);
        Assert.Equal("https://api.manage.microsoft.com//.default", claims.FindFirst("scope")?.Value);
        Assert.Equal("https://sim/contoso.onmicrosoft.com/v2.0", claims.FindFirst("iss")?.Value);
    }

    [Fact]
    public void Garbage_token_fails_verification()
    {
        using var key = new TokenSigningKey();
        Assert.False(key.TryVerify("not.a.jwt", out _));
        Assert.False(key.TryVerify("", out _));
    }

    [Fact]
    public void Jwks_exposes_one_rsa_signing_key()
    {
        using var key = new TokenSigningKey();
        var jwks = System.Text.Json.JsonDocument.Parse(key.GetJwksJson());
        var k = jwks.RootElement.GetProperty("keys")[0];
        Assert.Equal("RSA", k.GetProperty("kty").GetString());
        Assert.Equal("sig", k.GetProperty("use").GetString());
        Assert.Equal(key.KeyId, k.GetProperty("kid").GetString());
        Assert.False(string.IsNullOrEmpty(k.GetProperty("n").GetString()));
        Assert.False(string.IsNullOrEmpty(k.GetProperty("e").GetString()));
    }

    [Fact]
    public void Expired_token_fails_verification()
    {
        using var key = new TokenSigningKey();
        var token = key.IssueAccessToken("iss", "aud", "scope", TimeSpan.FromMinutes(-10));
        Assert.False(key.TryVerify(token, out _));
    }

    [Fact]
    public void Issued_token_carries_exp_claim()
    {
        using var key = new TokenSigningKey();
        var token = key.IssueAccessToken("iss", "aud", "scope", TimeSpan.FromHours(1));
        Assert.True(key.TryVerify(token, out var claims));
        Assert.NotNull(claims!.FindFirst("exp"));
    }

    [Fact]
    public void Token_signed_by_other_key_is_rejected()
    {
        using var keyA = new TokenSigningKey();
        using var keyB = new TokenSigningKey();
        var token = keyA.IssueAccessToken("iss", "aud", "scope", TimeSpan.FromHours(1));
        Assert.False(keyB.TryVerify(token, out _));
    }
}
