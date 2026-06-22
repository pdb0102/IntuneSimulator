using System.IO;
using ScepWright.Client;
using Xunit;

namespace ScepWright.Tests;

public class CliRouterTests {
    [Fact]
    public void Servers_add_then_list_round_trips() {
        string root;
        StringWriter outw;
        int add_code;
        int list_code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        add_code = CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "privpki" }, root, outw);
        list_code = CommandRouter.Run(new[] { "servers", "list" }, root, outw);

        Assert.Equal(0, add_code);
        Assert.Equal(0, list_code);
        Assert.Contains("privpki", outw.ToString());
        Assert.Contains("http://host/scep", outw.ToString());
    }

    [Fact]
    public void Unknown_command_returns_nonzero_and_usage() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        code = CommandRouter.Run(new[] { "frobnicate" }, root, outw);

        Assert.NotEqual(0, code);
        Assert.Contains("unknown command 'frobnicate'", outw.ToString());
        Assert.Contains("usage", outw.ToString().ToLowerInvariant());
    }

    [Fact]
    public void Unknown_flag_is_rejected() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        // A typo'd --keyspec (should be --key-spec) must error, not silently fall back to RSA.
        code = CommandRouter.Run(new[] { "get", "corp", "--subject", "CN=x", "--keyspec", "ec:p256" }, root, outw);

        Assert.NotEqual(0, code);
        Assert.Contains("unknown flag '--keyspec'", outw.ToString());
    }

    [Fact]
    public void Suite_verb_is_first_class() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        // `full` with no server is a usage error for the suite — NOT an unknown command.
        code = CommandRouter.Run(new[] { "full" }, root, outw);

        Assert.NotEqual(0, code);
        Assert.DoesNotContain("unknown command", outw.ToString());
        Assert.Contains("full <server>", outw.ToString());
    }

    [Fact]
    public void Config_set_rejects_invalid_key_spec() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        code = CommandRouter.Run(new[] { "config", "set", "key-spec", "not-a-real-spec" }, root, outw);

        Assert.NotEqual(0, code);
        Assert.Contains("invalid key-spec", outw.ToString());
    }

    [Fact]
    public void Min_rsa_bits_is_enforced_on_enroll() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "config", "set", "min-rsa-bits", "4096" }, root, outw);
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "h" }, root, outw);

        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "get", "h", "--subject", "CN=x", "--key-spec", "rsa:2048" }, root, outw);

        Assert.Equal(2, code);
        Assert.Contains("min-rsa-bits", outw.ToString());
    }

    [Fact]
    public void Bad_report_format_is_rejected_before_running() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "h" }, root, outw);

        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "full", "h", "--report-format", "garbage" }, root, outw);

        Assert.Equal(2, code);
        Assert.Contains("unknown report format", outw.ToString());
    }

    [Fact]
    public void Renew_rejects_unknown_variant() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "renew", "deadbeef", "--variant", "bogusvariant" }, root, outw);

        Assert.Equal(2, code);
        Assert.Contains("unknown --variant", outw.ToString());
    }

    [Fact]
    public void Servers_add_rejects_unknown_transport() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--transport", "sideways" }, root, outw);

        Assert.Equal(2, code);
        Assert.Contains("unknown --transport", outw.ToString());
    }

    [Fact]
    public void Config_show_uses_settable_kebab_keys() {
        string root;
        StringWriter outw;
        int code;

        root = Directory.CreateTempSubdirectory().FullName;
        outw = new StringWriter();

        CommandRouter.Run(new[] { "config", "set", "min-rsa-bits", "4096" }, root, outw);
        outw = new StringWriter();
        code = CommandRouter.Run(new[] { "config", "show" }, root, outw);

        Assert.Equal(0, code);
        Assert.Contains("key-spec:", outw.ToString());
        Assert.Contains("min-rsa-bits:     4096", outw.ToString());
    }
}
