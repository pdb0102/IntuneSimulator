namespace ScepWright.Core.Storage;

/// <summary>A persisted SCEP server entry in the registry.</summary>
public sealed class StoredServer {
    /// <summary>Gets or sets the local server identifier.</summary>
    public required string Id { get; set; }
    /// <summary>Gets or sets the SCEP endpoint URL.</summary>
    public required string Url { get; set; }
    /// <summary>Gets or sets an optional display name.</summary>
    public string? Name { get; set; }
    /// <summary>Gets or sets the CA identifier for multi-CA servers.</summary>
    public string? CaIdentifier { get; set; }
    /// <summary>Gets or sets whether to prefer HTTP POST for PKIOperation. Defaults to true.</summary>
    public bool PreferPost { get; set; } = true;
}
