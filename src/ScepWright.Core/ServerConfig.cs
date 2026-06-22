using System;

namespace ScepWright.Core;

/// <summary>Connection settings for a SCEP server endpoint.</summary>
public sealed class ServerConfig {
    /// <summary>Gets the local identifier for this server.</summary>
    public required string Id { get; init; }
    /// <summary>Gets the SCEP endpoint URL.</summary>
    public required Uri Url { get; init; }
    /// <summary>Gets the CA identifier passed to GetCACert, if the server hosts multiple CAs.</summary>
    public string? CaIdentifier { get; init; }
    /// <summary>Gets whether to prefer HTTP POST for PKIOperation. Defaults to true.</summary>
    public bool PreferPost { get; init; } = true;
}
