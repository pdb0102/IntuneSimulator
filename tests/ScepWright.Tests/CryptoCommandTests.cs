using System.IO;
using ScepWright.Client;
using Xunit;

namespace ScepWright.Tests;

public sealed class CryptoCommandTests {
    [Fact]
    public void Crypto_list_shows_pq() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "list" }, Path.GetTempPath(), output);
        Assert.Equal(0, code);
        Assert.Contains("ML-DSA-65", output.ToString());
        Assert.Contains("ML-KEM-768", output.ToString());
        Assert.Contains("SHA-256", output.ToString());
    }

    [Fact]
    public void Crypto_info_shows_tiers() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "info" }, Path.GetTempPath(), output);
        Assert.Equal(0, code);
        Assert.Contains("Tier A", output.ToString());
        Assert.Contains("Tier C", output.ToString());
        Assert.Contains("yes", output.ToString());
        Assert.Contains("crypto list", output.ToString());
    }

    [Fact]
    public void Crypto_unknown_verb_is_nonzero() {
        StringWriter output;
        int code;

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "crypto", "bogus" }, Path.GetTempPath(), output);
        Assert.NotEqual(0, code);
    }
}
