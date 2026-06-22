namespace ScepWright.Crypto;

/// <summary>SCEP CertRep failInfo codes (RFC 8894 §3.3.2.1).</summary>
public enum FailInfo {
    /// <summary>Unrecognized or unsupported algorithm.</summary>
    BadAlg = 0,
    /// <summary>Integrity check (signature) failed.</summary>
    BadMessageCheck = 1,
    /// <summary>Transaction not permitted or not supported.</summary>
    BadRequest = 2,
    /// <summary>signingTime attribute was not acceptable.</summary>
    BadTime = 3,
    /// <summary>No certificate matched the supplied criteria.</summary>
    BadCertId = 4,
    /// <summary>No failure (not a FAILURE response).</summary>
    None = -1
}
