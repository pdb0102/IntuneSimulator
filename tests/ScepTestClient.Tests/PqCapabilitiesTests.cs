using System.Linq;
using ScepTestClient.Crypto.BouncyCastle;
using ScepTestClient.CryptoApi;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class PqCapabilitiesTests {
    [Fact]
    public void Default_pqtiers_all_false() {
        CryptoCapabilities caps;

        caps = new CryptoCapabilities();
        Assert.False(caps.PqTiers.TierA);
        Assert.False(caps.PqTiers.TierB);
        Assert.False(caps.PqTiers.TierC);
    }

    [Fact]
    public void Bc_provider_advertises_pq() {
        BouncyCastleScepCrypto crypto;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(crypto.Capabilities.PqTiers.TierA);
        Assert.True(crypto.Capabilities.PqTiers.TierB);
        Assert.False(crypto.Capabilities.PqTiers.TierC);
        Assert.Contains("2.16.840.1.101.3.4.3.18", crypto.Capabilities.Signatures);
        Assert.Contains("2.16.840.1.101.3.4.3.18", crypto.Capabilities.AsymmetricKeys);
        Assert.Contains("2.16.840.1.101.3.4.4.2", crypto.Capabilities.Kem);
        Assert.Contains("1.2.840.113549.1.1.1", crypto.Capabilities.AsymmetricKeys);
    }
}
