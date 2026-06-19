namespace IntuneSimulator.Core;

/// <summary>Immutable startup configuration. Mutable behavior lives in <see cref="SimulatorState"/>.</summary>
public sealed record SimulatorOptions
{
    public string AuthPassword { get; init; } = "IntunePassw0rd!";
    public string Tenant { get; init; } = "contoso.onmicrosoft.com";
    public string AppId { get; init; } = "0000000a-0000-0000-c000-000000000000";
    /// <summary>Base64 of a PFX used for client-certificate auth validation. Null = cert auth disabled.</summary>
    public string? AuthCertificatePfxBase64 { get; init; }
    public string? AuthCertificatePassword { get; init; }
    /// <summary>Override the advertised base URL (scheme+host) when behind IIS/proxy. Null = derive from request.</summary>
    public string? AdvertisedBaseUrl { get; init; }
    public bool RevocationEnabled { get; init; } = true;
    public string? ChallengePasswordOverride { get; init; }
    public bool LogRequests { get; init; } = false;
}
