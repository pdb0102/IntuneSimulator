namespace ScepWright.Crypto;

/// <summary>SCEP pkiStatus attribute values (RFC 8894 §3.2.1.3).</summary>
public enum PkiStatus {
    /// <summary>Request granted; the response carries the certificate(s).</summary>
    Success = 0,
    /// <summary>Request rejected; see failInfo.</summary>
    Failure = 2,
    /// <summary>Request received but not yet processed (manual approval).</summary>
    Pending = 3
}
