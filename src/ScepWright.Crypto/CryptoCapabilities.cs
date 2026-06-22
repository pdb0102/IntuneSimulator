using System.Collections.Generic;

namespace ScepWright.Crypto;

/// <summary>The set of algorithm OIDs and PQ tiers a crypto provider advertises support for.</summary>
public sealed class CryptoCapabilities {
    /// <summary>Gets the supported digest algorithm OIDs.</summary>
    public IReadOnlyCollection<string> Digests { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the supported signature algorithm OIDs.</summary>
    public IReadOnlyCollection<string> Signatures { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the supported content-encryption algorithm OIDs.</summary>
    public IReadOnlyCollection<string> ContentEncryption { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the OIDs of recipient key types usable for key-transport enveloping.</summary>
    public IReadOnlyCollection<string> KeyTransport { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the supported KEM (key-encapsulation) algorithm OIDs.</summary>
    public IReadOnlyCollection<string> Kem { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the OIDs of recipient key types usable for key-agreement enveloping.</summary>
    public IReadOnlyCollection<string> KeyAgreement { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the supported asymmetric key-type OIDs for key generation.</summary>
    public IReadOnlyCollection<string> AsymmetricKeys { get; init; } = System.Array.Empty<string>();
    /// <summary>Gets the post-quantum tiers the provider supports.</summary>
    public PqTiers PqTiers { get; init; } = new PqTiers();
}
