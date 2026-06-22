using System.Linq;
using ScepWright.Core.Protocol;
using ScepWright.Core.Testing;
using ScepWright.Crypto;
using Xunit;

namespace ScepWright.Tests;

public sealed class PqOpinionSuggestTests {
    [Theory]
    [InlineData("ML-DSA-65", AlgorithmPosture.CuttingEdge)]
    [InlineData("SLH-DSA-128s", AlgorithmPosture.CuttingEdge)]
    [InlineData("RSA", AlgorithmPosture.Modern)]
    [InlineData("bogus", AlgorithmPosture.Unknown)]
    public void Classifies_signatures(string name, AlgorithmPosture expected) {
        Assert.Equal(expected, SecurityOpinion.ClassifySignature(name));
    }

    [Fact]
    public void Suggest_includes_pq_when_provider_supports_tier_a() {
        ScepCapabilities scep_caps;
        CryptoCapabilities crypto_caps;
        System.Collections.Generic.IReadOnlyList<string> lines;

        scep_caps = ScepCapabilities.Parse("SHA-256\nAES\n");
        crypto_caps = new CryptoCapabilities { PqTiers = new PqTiers(TierA: true) };
        lines = ServerSuggest.For("srv", scep_caps, crypto_caps);
        Assert.Contains(lines, l => l.Contains("ml-dsa:65"));
        Assert.Contains(lines, l => l.Contains("--digest SHA-256"));
    }

    [Fact]
    public void Suggest_old_overload_still_works_without_pq() {
        ScepCapabilities scep_caps;
        System.Collections.Generic.IReadOnlyList<string> lines;

        scep_caps = ScepCapabilities.Parse("SHA-256\nAES\n");
        lines = ServerSuggest.For("srv", scep_caps);
        Assert.DoesNotContain(lines, l => l.Contains("ml-dsa:65"));
        Assert.Contains(lines, l => l.Contains("--digest SHA-256"));
    }
}
