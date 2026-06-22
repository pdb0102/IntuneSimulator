using ScepWright.Client;

namespace ScepWright.Tests;

public class HelpKeySpecTests {
    [Fact]
    public void HelpUse_lists_key_spec_families() {
        string help;

        help = CommandRouter.HelpUse();

        Assert.Contains("ec:p256", help);
        Assert.Contains("ml-dsa", help);
        Assert.Contains("crypto info", help);
    }
}
