namespace ScepWright.Crypto;

/// <summary>
/// Post-quantum tier support advertised by a provider (spec §3.4, §14). Defaults to all-false.
/// </summary>
/// <param name="TierA">PQ signature subject keys (ML-DSA / SLH-DSA) with classical RSA transport.</param>
/// <param name="TierB">PQ signing of the outer CMS message.</param>
/// <param name="TierC">PQ key-encapsulation (ML-KEM) enveloping.</param>
public sealed record PqTiers(bool TierA = false, bool TierB = false, bool TierC = false);
