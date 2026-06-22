namespace ScepWright.Core.Storage;

/// <summary>One audit-history entry recording a SCEP operation and its outcome.</summary>
public sealed class UseRecord {
    /// <summary>Gets or sets the operation name (e.g. "Enroll").</summary>
    public string Operation { get; set; } = string.Empty;
    /// <summary>Gets or sets the resulting pkiStatus.</summary>
    public string PkiStatus { get; set; } = string.Empty;
    /// <summary>Gets or sets how long the operation took, in milliseconds.</summary>
    public long TimingMs { get; set; }
    /// <summary>Gets or sets the issued certificate id, if any.</summary>
    public string? CertId { get; set; }
    /// <summary>Gets or sets the failInfo when the operation failed.</summary>
    public string? FailInfo { get; set; }
    /// <summary>Gets or sets the SCEP transaction id.</summary>
    public string? TransactionId { get; set; }
}
