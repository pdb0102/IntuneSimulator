using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core;

public static class UrlHelpers
{
    /// <summary>Externally-reachable base URL (scheme://host[:port]) for building self-referential URLs.</summary>
    public static string BaseUrl(this HttpContext ctx)
    {
        var advertised = ctx.RequestServices.GetService(typeof(SimulatorOptions)) as SimulatorOptions;
        if (!string.IsNullOrEmpty(advertised?.AdvertisedBaseUrl))
            return advertised!.AdvertisedBaseUrl!.TrimEnd('/');
        return $"{ctx.Request.Scheme}://{ctx.Request.Host}";
    }
}
