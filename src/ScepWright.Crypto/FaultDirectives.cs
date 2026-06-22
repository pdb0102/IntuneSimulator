namespace ScepWright.Crypto;

/// <summary>
/// Deliberate fault injection for negative/conformance testing. Attached to a request via
/// <c>ScepRequestBuilder.AllowFaults(...)</c> and applied only inside the provider's
/// <c>if (faults != null)</c> encode branch.
/// </summary>
public sealed class FaultDirectives {
    /// <summary>Sign the CMS with a throwaway key so the signature fails to verify (expects badMessageCheck).</summary>
    public bool CorruptSignature { get; set; }

    /// <summary>Offset the CMS signingTime authenticated attribute from now (e.g. +2h) to provoke badTime.</summary>
    public System.TimeSpan? SigningTimeSkew { get; set; }

    /// <summary>Garble the inner payload before enveloping so no PKCS#10 parses (expects badRequest).</summary>
    public bool CorruptInnerContent { get; set; }
}
