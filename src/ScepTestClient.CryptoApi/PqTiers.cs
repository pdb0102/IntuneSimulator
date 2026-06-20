namespace ScepTestClient.CryptoApi;

// PQ tier support advertised by a provider (spec §3.4, §14). Additive — defaults to all-false so
// existing/external CryptoCapabilities consumers are unaffected.
public sealed record PqTiers(bool TierA = false, bool TierB = false, bool TierC = false);
