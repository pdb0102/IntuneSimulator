namespace IntuneSimulator.Core;

/// <summary>Immutable startup configuration. Mutable behavior lives in <see cref="SimulatorState"/>.</summary>
public sealed record SimulatorOptions
{
    /// <summary>Gets the password accepted as the client-credentials secret.</summary>
    public string AuthPassword { get; init; } = "IntunePassw0rd!";
    /// <summary>Gets the tenant name advertised in discovery documents.</summary>
    public string Tenant { get; init; } = "contoso.onmicrosoft.com";
    /// <summary>Gets the application (client) id the simulator expects.</summary>
    public string AppId { get; init; } = "0000000a-0000-0000-c000-000000000000";
    /// <summary>Gets the Base64 of a PFX used for client-certificate auth validation. Null = cert auth disabled.</summary>
    public string? AuthCertificatePfxBase64 { get; init; }
    /// <summary>Gets the password protecting <see cref="AuthCertificatePfxBase64"/>.</summary>
    public string? AuthCertificatePassword { get; init; }
    /// <summary>Gets the advertised base URL (scheme+host) override used when behind IIS/proxy. Null = derive from request.</summary>
    public string? AdvertisedBaseUrl { get; init; }
    /// <summary>Gets a value indicating whether the PKI-connector revocation endpoints are enabled.</summary>
    public bool RevocationEnabled { get; init; } = true;
    /// <summary>Gets an explicit SCEP challenge password. Null = derive from the auth password.</summary>
    public string? ChallengePasswordOverride { get; init; }
    /// <summary>Gets a value indicating whether each request is logged to the configured sink.</summary>
    public bool LogRequests { get; init; } = false;
}
