using ScepWright.Crypto;
using Xunit;

namespace ScepWright.Tests;

public sealed class PqAlgorithmsTests {
    [Theory]
    [InlineData("ML-DSA-44", "2.16.840.1.101.3.4.3.17", AlgorithmKind.Signature)]
    [InlineData("ML-DSA-65", "2.16.840.1.101.3.4.3.18", AlgorithmKind.Signature)]
    [InlineData("ML-DSA-87", "2.16.840.1.101.3.4.3.19", AlgorithmKind.Signature)]
    [InlineData("ML-KEM-512", "2.16.840.1.101.3.4.4.1", AlgorithmKind.Kem)]
    [InlineData("ML-KEM-768", "2.16.840.1.101.3.4.4.2", AlgorithmKind.Kem)]
    [InlineData("ML-KEM-1024", "2.16.840.1.101.3.4.4.3", AlgorithmKind.Kem)]
    public void Pq_entries_resolve(string name, string oid, AlgorithmKind kind) {
        Assert.Equal(oid, Algorithms.OidFor(name));
        Assert.Equal(name, Algorithms.NameFor(oid));
        Assert.Equal(kind, Algorithms.KindOf(oid));
    }

    [Fact]
    public void Existing_entries_unchanged() {
        Assert.Equal("2.16.840.1.101.3.4.2.1", Algorithms.OidFor("SHA-256"));
        Assert.Equal("1.2.840.113549.1.1.1", Algorithms.OidFor("RSA"));
    }
}
