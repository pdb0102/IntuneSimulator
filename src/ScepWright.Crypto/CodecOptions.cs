namespace ScepWright.Crypto;

/// <summary>Flags relaxing strictness when decoding a SCEP PKI message.</summary>
[Flags]
public enum CodecOptions {
    /// <summary>Enforce signature verification and reject legacy/insecure algorithms.</summary>
    Strict = 0,
    /// <summary>Tolerate minor structural deviations rather than failing the decode.</summary>
    LenientParsing = 1,
    /// <summary>Do not verify the outer CMS signature.</summary>
    SkipSignatureVerification = 2,
    /// <summary>Accept legacy/weak algorithms (e.g. SHA-1, 3DES) without error.</summary>
    AllowLegacyAlgorithms = 4,
}
