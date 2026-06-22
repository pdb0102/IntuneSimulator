using ScepWright.Client;

namespace ScepWright.Tests;

public class HelpSplitTests {
    [Fact]
    public void HelpUse_lists_use_it_commands_only() {
        string help;

        help = CommandRouter.HelpUse();

        Assert.Contains("Use it", help);
        Assert.Contains("get <serverId>", help);
        Assert.Contains("enroll <serverId>", help);
        Assert.Contains("renew <certId>", help);
        Assert.Contains("certs list", help);
        Assert.Contains("config set", help);
        Assert.Contains("crypto info", help);
        Assert.DoesNotContain("getcacaps", help);
        Assert.DoesNotContain("test <lifecycle", help);
    }

    [Fact]
    public void HelpTest_lists_test_it_commands_only() {
        string help;

        help = CommandRouter.HelpTest();

        Assert.Contains("Test with it", help);
        Assert.Contains("getcacaps <serverId>", help);
        Assert.Contains("getcacert <serverId>", help);
        Assert.Contains("getnextcacert <serverId>", help);
        Assert.Contains("poll <serverId>", help);
        Assert.Contains("getcert <serverId>", help);
        Assert.Contains("getcrl <serverId>", help);
        Assert.Contains("servers suggest", help);
        Assert.Contains("full|lifecycle|probe <serverId>", help);
        Assert.Contains("run <scenario.json>", help);
        Assert.DoesNotContain("crypto info", help);
    }

    [Fact]
    public void Unknown_command_prints_combined_help_with_usage() {
        System.IO.StringWriter outw;
        int code;
        string text;

        outw = new System.IO.StringWriter();
        code = CommandRouter.Run(new[] { "bogus-noun" }, System.IO.Path.GetTempPath(), outw);
        text = outw.ToString();

        Assert.Equal(2, code);
        Assert.Contains("usage", text.ToLowerInvariant());
        Assert.Contains("scepclient", text);
        Assert.Contains("Use it", text);
        Assert.Contains("Test with it", text);
    }
}
