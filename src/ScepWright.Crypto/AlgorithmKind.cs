namespace ScepWright.Crypto;

/// <summary>The role an algorithm plays within SCEP/CMS.</summary>
public enum AlgorithmKind {
    /// <summary>A message-digest / hash algorithm.</summary>
    Digest,
    /// <summary>A digital-signature algorithm.</summary>
    Signature,
    /// <summary>A symmetric content-encryption algorithm.</summary>
    ContentEncryption,
    /// <summary>An asymmetric key-transport (key-wrap) algorithm.</summary>
    KeyTransport,
    /// <summary>A key-encapsulation mechanism (post-quantum).</summary>
    Kem,
    /// <summary>An asymmetric key type (e.g. RSA, EC).</summary>
    AsymmetricKey,
}
