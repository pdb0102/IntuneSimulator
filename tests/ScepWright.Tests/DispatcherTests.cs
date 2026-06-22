using System.IO;
using ScepWright.Dispatcher;

namespace ScepWright.Tests;

public class DispatcherTests {
    private static (int code, string text) RunDispatcher(params string[] args) {
        StringWriter outw;
        int code;

        outw = new StringWriter();
        code = DispatcherCli.Run(args, outw);
        return (code, outw.ToString());
    }

    [Fact]
    public void Bare_invocation_prints_unified_help() {
        (int code, string text) result;

        result = RunDispatcher();

        Assert.Equal(0, result.code);
        Assert.Contains("scepwright — SCEP testing suite", result.text);
        Assert.Contains("Use it", result.text);
        Assert.Contains("Test with it", result.text);
        Assert.Contains("UNTRUSTED", result.text);
        // Unified help speaks as scepwright, not scepca: server section reframed, client groups prefixed.
        Assert.Contains("Usage: scepwright server", result.text);
        Assert.Contains("run as: scepwright client", result.text);
        Assert.DoesNotContain("Usage: scepca", result.text);
    }

    [Fact]
    public void Help_verb_matches_unified_help() {
        (int code, string text) result;

        result = RunDispatcher("help");

        Assert.Equal(0, result.code);
        Assert.Contains("scepwright — SCEP testing suite", result.text);
    }

    [Fact]
    public void Unknown_verb_returns_two_and_unified_help() {
        (int code, string text) result;

        result = RunDispatcher("bogus");

        Assert.Equal(2, result.code);
        Assert.Contains("Usage: scepwright", result.text);
    }

    [Fact]
    public void Client_door_prints_HelpUse_not_HelpTest() {
        (int code, string text) result;

        result = RunDispatcher("client");

        Assert.Equal(0, result.code);
        Assert.Contains("Use it", result.text);
        Assert.DoesNotContain("Test with it", result.text);
    }

    [Fact]
    public void Client_help_token_prints_HelpUse() {
        (int code, string text) result;

        result = RunDispatcher("client", "help");

        Assert.Equal(0, result.code);
        Assert.Contains("Use it", result.text);
    }

    [Fact]
    public void Test_door_prints_HelpTest_not_HelpUse() {
        (int code, string text) result;

        result = RunDispatcher("test");

        Assert.Equal(0, result.code);
        Assert.Contains("Test with it", result.text);
        Assert.DoesNotContain("Use it", result.text);
    }

    [Fact]
    public void Client_door_forwards_to_engine() {
        string tmp;
        (int code, string text) result;

        tmp = Path.Combine(Path.GetTempPath(), "scepwright-disp-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        try {
            result = RunDispatcher("client", "servers", "list", "--data-dir", tmp);
            Assert.Equal(0, result.code);
        } finally {
            Directory.Delete(tmp, recursive: true);
        }
    }

    [Fact]
    public void Server_door_help_shows_scepwright_server_help() {
        (int code, string text) result;

        result = RunDispatcher("server", "--help");

        Assert.Equal(0, result.code);
        Assert.Contains("Usage: scepwright server", result.text);
        Assert.Contains("UNTRUSTED", result.text);
        Assert.DoesNotContain("Usage: scepca", result.text);
    }
}
