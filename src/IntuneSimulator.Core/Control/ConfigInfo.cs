using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core.Control;

/// <summary>Builds the set of URLs/values a user must configure in their product to point at this simulator.</summary>
public static class ConfigInfo
{
    /// <summary>Builds the configuration object (URLs, tenant, app id, passwords) for the current request's base URL.</summary>
    public static object Build(HttpContext ctx, SimulatorState state)
    {
        var b = ctx.BaseUrl();
        return new
        {
            urls = new
            {
                authUrl = b + "/",                 // ScepIntuneAuthenticationAuthorityResourceURL (must be https for MSAL)
                msGraphUrl = b + "/",              // ScepIntuneMSGraphResourceURL
                graphUrl = b + "/",               // ScepIntuneGraphResourceURL (AAD graph fallback)
                intuneResourceUrl = b + "/",      // ScepIntuneResourceURL (token scope only)
                tenant = state.Options.Tenant,    // ScepIntuneTenantName
                appId = state.Options.AppId,      // ScepIntuneApplicationId
                authPassword = state.AuthPassword // ScepIntuneApplicationSecret (secret auth)
            },
            challengePassword = state.ChallengePassword,
            cannedScepCode = state.CannedScepCode,
            revocationEnabled = state.Options.RevocationEnabled
        };
    }
}
