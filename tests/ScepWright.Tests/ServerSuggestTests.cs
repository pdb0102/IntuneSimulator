using ScepWright.Core.Protocol;
using ScepWright.Core.Testing;
using ScepWright.Crypto.BouncyCastle;

namespace ScepWright.Tests;

public class ServerSuggestTests {
    [Fact]
    public void Suggests_scepclient_brand_and_ec_when_capable() {
        ScepCapabilities caps;
        System.Collections.Generic.IReadOnlyList<string> lines;
        string joined;

        caps = ScepCapabilities.Parse("POSTPKIOperation\nSHA-256\nAES\n");
        lines = ServerSuggest.For("srv", caps, new BouncyCastleScepCrypto().Capabilities);
        joined = string.Join("\n", lines);

        Assert.Contains("scepclient enroll", joined);
        Assert.DoesNotContain("sceptest", joined);
        Assert.Contains("ec:p256", joined);
        Assert.Contains("ml-dsa", joined);
        Assert.Contains("slh-dsa", joined);
    }

    // A suggested SHA-1 enroll line must be flagged as weak, not presented as a neutral option.
    [Fact]
    public void Sha1_enroll_line_is_flagged_weak() {
        ScepCapabilities caps;
        System.Collections.Generic.IReadOnlyList<string> lines;
        string sha1_line;

        caps = ScepCapabilities.Parse("POSTPKIOperation\nSHA-1\nAES\n");
        lines = ServerSuggest.For("srv", caps, new BouncyCastleScepCrypto().Capabilities);

        sha1_line = string.Empty;
        foreach (string line in lines) {
            if (line.Contains("--digest SHA-1")) { sha1_line = line; }
        }
        Assert.NotEqual(string.Empty, sha1_line);
        Assert.Contains("weak", sha1_line.ToLowerInvariant());
    }

    // ML-KEM is a KEM (a response-enveloping recipient algorithm), not a signing/subject key, so
    // `scepclient enroll --key-spec ml-kem:768` can never work. Even when the provider is Tier C capable,
    // suggest must not mention ml-kem at all (it would only mislead).
    [Fact]
    public void Does_not_suggest_ml_kem() {
        ScepCapabilities caps;
        BouncyCastleScepCrypto crypto;
        System.Collections.Generic.IReadOnlyList<string> lines;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(crypto.Capabilities.PqTiers.TierC, "provider must be ML-KEM (Tier C) capable for this test to be meaningful");

        caps = ScepCapabilities.Parse("POSTPKIOperation\nSHA-256\nAES\n");
        lines = ServerSuggest.For("srv", caps, crypto.Capabilities);

        Assert.DoesNotContain(lines, l => l.Contains("ml-kem"));
    }

    [Fact]
    public void Classifies_ec_as_modern() {
        Assert.Equal(AlgorithmPosture.Modern, SecurityOpinion.ClassifySignature("ECDSA-P256"));
    }
}
