using System.Text.Json.Serialization;

namespace IntuneSimulator.Core.Revocation;

/// <summary>A single certificate revocation request queued for a PKI connector.</summary>
public sealed class RevocationRequestItem
{
    /// <summary>Gets or sets the opaque request context correlating download and upload.</summary>
    [JsonPropertyName("requestContext")]
    public string RequestContext { get; set; } = "";

    /// <summary>Gets or sets the serial number of the certificate to revoke.</summary>
    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = "";

    /// <summary>Gets or sets the issuer name of the certificate to revoke.</summary>
    [JsonPropertyName("issuerName")]
    public string? IssuerName { get; set; }

    /// <summary>Gets or sets the CA configuration identifier.</summary>
    [JsonPropertyName("caConfiguration")]
    public string? CaConfiguration { get; set; }
}

/// <summary>Envelope for a revocation download request.</summary>
public sealed class DownloadBody { /// <summary>Gets or sets the download parameters.</summary>
public DownloadParameters? DownloadParameters { get; set; } }

/// <summary>Parameters controlling a revocation download.</summary>
public sealed class DownloadParameters { /// <summary>Gets or sets the maximum number of requests to return.</summary>
public int MaxRequests { get; set; } = 50; /// <summary>Gets or sets the issuer name to filter by. Null = no filter.</summary>
public string? IssuerName { get; set; } }

/// <summary>Envelope for a revocation result upload.</summary>
public sealed class UploadBody { /// <summary>Gets or sets the per-request results.</summary>
public List<UploadResult> Results { get; set; } = new(); }

/// <summary>Outcome of processing a single revocation request.</summary>
public sealed class UploadResult
{
    /// <summary>Gets or sets the request context this result corresponds to.</summary>
    public string RequestContext { get; set; } = "";
    /// <summary>Gets or sets a value indicating whether the revocation succeeded.</summary>
    public bool Succeeded { get; set; }
    /// <summary>Gets or sets the error code when the revocation failed.</summary>
    public string? ErrorCode { get; set; }
    /// <summary>Gets or sets the error message when the revocation failed.</summary>
    public string? ErrorMessage { get; set; }
}
