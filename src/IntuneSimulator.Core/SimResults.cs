using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace IntuneSimulator.Core;

/// <summary>
/// JSON result helper used by all simulator endpoints. Bypasses Results.Json, which throws
/// "PipeWriter does not implement UnflushedBytes" under the WebApplicationFactory test host.
/// Serializes with PropertyNamingPolicy = null so names are emitted verbatim: snake_case for the
/// AAD/OAuth anonymous types, and the exact [JsonPropertyName] values for typed DTOs.
/// </summary>
public static class SimResults
{
    private static readonly JsonSerializerOptions _verbatim = new() { PropertyNamingPolicy = null };

    /// <summary>Serializes <paramref name="value"/> to JSON verbatim and returns it as a content result with the given status code.</summary>
    public static IResult Json(object value, int statusCode = 200)
    {
        var body = JsonSerializer.Serialize(value, _verbatim);
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, statusCode);
    }
}
