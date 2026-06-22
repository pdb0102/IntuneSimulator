namespace ScepWright.Core.Testing;

/// <summary>The kind of deliberate fault a compliance check injects into a request.</summary>
public enum FaultKind {
    /// <summary>A forbidden digest algorithm (MD5).</summary>
    ForbiddenAlgorithm,
    /// <summary>A tampered CMS signature.</summary>
    CorruptedSignature,
    /// <summary>A signingTime skewed beyond tolerance.</summary>
    SkewedSigningTime,
    /// <summary>An incorrect challenge password.</summary>
    WrongChallenge,
    /// <summary>A GetCert for an unknown serial.</summary>
    UnknownCertId,
    /// <summary>An unparseable inner CSR.</summary>
    MalformedRequest,
    /// <summary>A RenewalReq sent when the Renewal capability is not advertised.</summary>
    RenewalNotAdvertised,
    /// <summary>A request enveloped with a weak cipher (DES-EDE3-CBC).</summary>
    WeakContentEncryption,
    /// <summary>A PKCSReq for an arbitrary/unauthorized subject.</summary>
    SpoofedSubject,
}
