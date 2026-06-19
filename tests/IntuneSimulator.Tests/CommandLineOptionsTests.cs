using IntuneSimulator.Host;
using Xunit;

namespace IntuneSimulator.Tests;

public class CommandLineOptionsTests
{
    [Fact]
    public void Parses_known_flags()
    {
        var cfg = CommandLineOptions.Parse(new[]
        {
            "--http-port", "9000", "--https-port", "9443",
            "--auth-password", "p@ss", "--tenant", "t.onmicrosoft.com",
            "--app-id", "abc", "--no-revocation", "--failure-mode", "manual",
        });
        Assert.Equal(9000, cfg.HttpPort);
        Assert.Equal(9443, cfg.HttpsPort);
        Assert.Equal("p@ss", cfg.Options.AuthPassword);
        Assert.Equal("t.onmicrosoft.com", cfg.Options.Tenant);
        Assert.Equal("abc", cfg.Options.AppId);
        Assert.False(cfg.Options.RevocationEnabled);
        Assert.Equal("manual", cfg.FailureMode);
    }

    [Fact]
    public void Defaults_are_practical()
    {
        var cfg = CommandLineOptions.Parse(System.Array.Empty<string>());
        Assert.Equal(8080, cfg.HttpPort);
        Assert.Equal(8443, cfg.HttpsPort);
        Assert.Equal("IntunePassw0rd!", cfg.Options.AuthPassword);
        Assert.True(cfg.Options.RevocationEnabled);
        Assert.Equal("off", cfg.FailureMode);
    }

    [Fact]
    public void Unknown_flag_throws_with_message()
    {
        var ex = Assert.Throws<System.ArgumentException>(() => CommandLineOptions.Parse(new[] { "--nope" }));
        Assert.Contains("--nope", ex.Message);
    }

    [Fact]
    public void Parses_advertised_url_and_challenge_password()
    {
        var cfg = CommandLineOptions.Parse(new[]
        {
            "--advertised-base-url", "https://sim.example:8443",
            "--challenge-password", "Q0hBTExFTkdF",
        });
        Assert.Equal("https://sim.example:8443", cfg.Options.AdvertisedBaseUrl);
        Assert.Equal("Q0hBTExFTkdF", cfg.Options.ChallengePasswordOverride);
    }

    [Fact]
    public void Skips_hosting_style_kv_args()
    {
        // Any --key=value form arg (as injected by the test host) is ignored, not an error.
        var cfg = CommandLineOptions.Parse(new[]
        {
            "--environment=Development", "--contentRoot=/tmp/x", "--some-future-host-arg=42",
            "--http-port", "9100",
        });
        Assert.Equal(9100, cfg.HttpPort);
    }

    [Fact]
    public void Request_logging_defaults_on_and_can_be_disabled()
    {
        Assert.True(CommandLineOptions.Parse(System.Array.Empty<string>()).Options.LogRequests);
        Assert.False(CommandLineOptions.Parse(new[] { "--no-request-log" }).Options.LogRequests);
    }
}
