using System.Text.Json.Serialization;

namespace IntuneSimulator.Core.Revocation;

public sealed class RevocationRequestItem
{
    [JsonPropertyName("requestContext")]
    public string RequestContext { get; set; } = "";

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; set; } = "";

    [JsonPropertyName("issuerName")]
    public string? IssuerName { get; set; }

    [JsonPropertyName("caConfiguration")]
    public string? CaConfiguration { get; set; }
}

public sealed class DownloadBody { public DownloadParameters? DownloadParameters { get; set; } }
public sealed class DownloadParameters { public int MaxRequests { get; set; } = 50; public string? IssuerName { get; set; } }

public sealed class UploadBody { public List<UploadResult> Results { get; set; } = new(); }
public sealed class UploadResult
{
    public string RequestContext { get; set; } = "";
    public bool Succeeded { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
}
