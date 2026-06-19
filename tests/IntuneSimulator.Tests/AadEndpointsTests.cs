using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using IntuneSimulator.Core;
using IntuneSimulator.Core.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace IntuneSimulator.Tests;

public class AadEndpointsTests
{
    private const string Tenant = "contoso.onmicrosoft.com";

    [Fact]
    public async Task Instance_discovery_lists_host_alias()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var doc = JsonDocument.Parse(await c.GetStringAsync("/common/discovery/instance?api-version=1.1"));
        var meta = doc.RootElement.GetProperty("metadata")[0];
        var aliases = meta.GetProperty("aliases").EnumerateArray().Select(a => a.GetString());
        Assert.Contains("localhost", aliases); // CreateClient uses http://localhost
        Assert.True(doc.RootElement.TryGetProperty("tenant_discovery_endpoint", out _));
    }

    [Fact]
    public async Task Openid_config_points_back_to_simulator()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var doc = JsonDocument.Parse(await c.GetStringAsync($"/{Tenant}/v2.0/.well-known/openid-configuration"));
        Assert.EndsWith($"/{Tenant}/oauth2/v2.0/token", doc.RootElement.GetProperty("token_endpoint").GetString());
        Assert.EndsWith($"/{Tenant}/discovery/v2.0/keys", doc.RootElement.GetProperty("jwks_uri").GetString());
        Assert.Contains(Tenant, doc.RootElement.GetProperty("issuer").GetString());
    }

    [Fact]
    public async Task Jwks_served()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var doc = JsonDocument.Parse(await c.GetStringAsync($"/{Tenant}/discovery/v2.0/keys"));
        Assert.Equal("RSA", doc.RootElement.GetProperty("keys")[0].GetProperty("kty").GetString());
    }

    [Fact]
    public async Task Token_with_correct_secret_issues_verifiable_token()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync($"/{Tenant}/oauth2/v2.0/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "app",
            ["client_secret"] = "IntunePassw0rd!",
            ["scope"] = "https://api.manage.microsoft.com//.default",
        }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("Bearer", doc.RootElement.GetProperty("token_type").GetString());
        var token = doc.RootElement.GetProperty("access_token").GetString()!;
        var key = f.Services.GetRequiredService<TokenSigningKey>();
        Assert.True(key.TryVerify(token, out _));
    }

    [Fact]
    public async Task Token_with_wrong_secret_is_invalid_client()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync($"/{Tenant}/oauth2/v2.0/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "app",
            ["client_secret"] = "wrong",
            ["scope"] = "https://api.manage.microsoft.com//.default",
        }));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("invalid_client", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_with_cert_assertion_issues_verifiable_token()
    {
        using var cert = TestCerts.CreateSelfSigned("CN=client");
        var pfx = cert.Export(X509ContentType.Pfx, "pw");
        var opts = new SimulatorOptions
        {
            AuthCertificatePfxBase64 = Convert.ToBase64String(pfx),
            AuthCertificatePassword = "pw",
        };
        using var f = new SimulatorAppFactory(opts);
        using var c = f.CreateClient();

        string tokenEndpoint = $"http://localhost/{Tenant}/oauth2/v2.0/token";
        var assertion = MakeClientAssertion(cert, "app", tokenEndpoint);

        var resp = await c.PostAsync($"/{Tenant}/oauth2/v2.0/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "app",
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = assertion,
            ["scope"] = "https://api.manage.microsoft.com//.default",
        }));

        Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var token = doc.RootElement.GetProperty("access_token").GetString()!;
        Assert.True(f.Services.GetRequiredService<TokenSigningKey>().TryVerify(token, out _));
    }

    [Fact]
    public async Task Token_with_wrong_grant_type_is_rejected()
    {
        using var f = new SimulatorAppFactory();
        using var c = f.CreateClient();
        var resp = await c.PostAsync($"/{Tenant}/oauth2/v2.0/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "app",
            ["client_secret"] = "IntunePassw0rd!",
            ["scope"] = "https://api.manage.microsoft.com//.default",
        }));
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("unsupported_grant_type", doc.RootElement.GetProperty("error").GetString());
    }

    private static string MakeClientAssertion(X509Certificate2 cert, string clientId, string audience)
    {
        var now = DateTime.UtcNow;
        var creds = new SigningCredentials(new X509SecurityKey(cert), SecurityAlgorithms.RsaSha256);
        var jwt = new JwtSecurityToken(
            issuer: clientId, audience: audience,
            claims: new[] { new Claim("sub", clientId), new Claim("jti", Guid.NewGuid().ToString()) },
            notBefore: now.AddMinutes(-5), expires: now.AddMinutes(10), signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
