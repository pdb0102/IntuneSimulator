namespace ScepWright.Core;

/// <summary>The shape of a renewal request: which message type, signer, and subject key are used.</summary>
public enum RenewalVariant {
    /// <summary>RenewalReq(17), signed by the existing cert+key, with a new subject key.</summary>
    Proper,
    /// <summary>PKCSReq(19), self-signed with a new key plus challenge, same subject DN.</summary>
    ReenrollSameSubject,
    /// <summary>PKCSReq(19), signed by the existing cert+key, with a new subject key.</summary>
    RenewalShapedPkcsReq,
    /// <summary>RenewalReq(17), signed by the existing cert+key, reusing the existing key.</summary>
    SameKey,
    /// <summary>RenewalReq(17), signed by an expired existing cert (negative test).</summary>
    Expired,
}
