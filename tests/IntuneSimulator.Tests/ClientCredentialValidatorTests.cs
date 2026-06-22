using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Auth;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace IntuneSimulator.Tests;

public class ClientCredentialValidatorTests
{
    private const string TokenEndpoint = "https://sim/contoso.onmicrosoft.com/oauth2/v2.0/token";

    private static SimulatorState StateWithCert(out X509Certificate2 cert)
    {
        cert = TestCerts.CreateSelfSigned("CN=intune-test");
        var pfx = cert.Export(X509ContentType.Pfx, "pfx-pw");
        return new SimulatorState(new SimulatorOptions
        {
            AuthPassword = "IntunePassw0rd!",
            AuthCertificatePfxBase64 = Convert.ToBase64String(pfx),
            AuthCertificatePassword = "pfx-pw",
        });
    }

    [Fact]
    public void Correct_secret_is_valid()
    {
        var state = new SimulatorState(new SimulatorOptions { AuthPassword = "IntunePassw0rd!" });
        var v = new ClientCredentialValidator();
        Assert.True(v.ValidateSecret(state, "app", "IntunePassw0rd!", out _));
    }

    [Fact]
    public void Wrong_secret_is_invalid()
    {
        var state = new SimulatorState(new SimulatorOptions { AuthPassword = "IntunePassw0rd!" });
        var v = new ClientCredentialValidator();
        Assert.False(v.ValidateSecret(state, "app", "bad", out var reason));
        Assert.False(string.IsNullOrEmpty(reason));
    }

    [Fact]
    public void Assertion_signed_by_configured_cert_is_valid()
    {
        var state = StateWithCert(out var cert);
        var assertion = MakeAssertion(cert, clientId: "app", audience: TokenEndpoint, expired: false);
        var v = new ClientCredentialValidator();
        Assert.True(v.ValidateClientAssertion(state, "app", assertion, TokenEndpoint, out var reason), reason);
    }

    [Fact]
    public void Assertion_from_other_cert_is_invalid()
    {
        var state = StateWithCert(out _);
        var other = TestCerts.CreateSelfSigned("CN=attacker");
        var assertion = MakeAssertion(other, "app", TokenEndpoint, expired: false);
        var v = new ClientCredentialValidator();
        Assert.False(v.ValidateClientAssertion(state, "app", assertion, TokenEndpoint, out _));
    }

    [Fact]
    public void Expired_assertion_is_invalid()
    {
        var state = StateWithCert(out var cert);
        var assertion = MakeAssertion(cert, "app", TokenEndpoint, expired: true);
        var v = new ClientCredentialValidator();
        Assert.False(v.ValidateClientAssertion(state, "app", assertion, TokenEndpoint, out _));
    }

    [Fact]
    public void Cert_auth_with_no_cert_configured_is_invalid()
    {
        var state = new SimulatorState(new SimulatorOptions { AuthPassword = "IntunePassw0rd!" });
        var v = new ClientCredentialValidator();
        Assert.False(v.ValidateClientAssertion(state, "app", "any.jwt.here", TokenEndpoint, out var reason));
        Assert.False(string.IsNullOrEmpty(reason));
    }

    [Fact]
    public void Assertion_with_wrong_audience_is_invalid()
    {
        var state = StateWithCert(out var cert);
        var assertion = MakeAssertion(cert, "app", "https://wrong.example/oauth2/v2.0/token", expired: false);
        var v = new ClientCredentialValidator();
        Assert.False(v.ValidateClientAssertion(state, "app", assertion, TokenEndpoint, out _));
    }

    [Fact]
    public void Assertion_with_mismatched_sub_is_invalid()
    {
        var state = StateWithCert(out var cert);
        var assertion = MakeAssertion(cert, "app", TokenEndpoint, expired: false, sub: "different-client");
        var v = new ClientCredentialValidator();
        Assert.False(v.ValidateClientAssertion(state, "app", assertion, TokenEndpoint, out var reason));
        Assert.Contains("sub", reason);
    }

    private static string MakeAssertion(X509Certificate2 cert, string clientId, string audience, bool expired, string? sub = null)
    {
        var now = DateTime.UtcNow;
        var creds = new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256);
        var jwt = new JwtSecurityToken(
            issuer: clientId, audience: audience,
            claims: new[] { new System.Security.Claims.Claim("sub", sub ?? clientId), new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString()) },
            notBefore: expired ? now.AddMinutes(-20) : now.AddMinutes(-5),
            expires: expired ? now.AddMinutes(-10) : now.AddMinutes(10),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
