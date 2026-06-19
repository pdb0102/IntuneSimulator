using Microsoft.Identity.Client;
using Microsoft.Intune; // IAccessTokenProvider from the copied sample

namespace IntuneSimulator.Tests.E2E;

/// <summary>Implements the sample's IAccessTokenProvider using a real MSAL confidential client (mirrors the product).</summary>
public sealed class MsalTokenProvider : IAccessTokenProvider
{
    private readonly IConfidentialClientApplication _app;
    public MsalTokenProvider(IConfidentialClientApplication app) => _app = app;
    public async Task<string> AcquireTokenAsync(string[] scopes)
        => (await _app.AcquireTokenForClient(scopes).ExecuteAsync()).AccessToken;
}

/// <summary>Routes MSAL's own HTTP through our cert-trusting client.</summary>
public sealed class TrustingMsalHttpFactory : IMsalHttpClientFactory
{
    private readonly System.Net.Http.HttpClient _client;
    public TrustingMsalHttpFactory(System.Net.Http.HttpClient client) => _client = client;
    public System.Net.Http.HttpClient GetHttpClient() => _client;
}
