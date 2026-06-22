using IntuneSimulator.Core;

namespace IntuneSimulator.Host;

/// <summary>Resolved host configuration parsed from the command line.</summary>
public sealed class HostConfig
{
    /// <summary>Gets or sets the HTTP listen port.</summary>
    public int HttpPort { get; set; } = 8080;
    /// <summary>Gets or sets the HTTPS listen port.</summary>
    public int HttpsPort { get; set; } = 8443;
    /// <summary>Gets or sets the path to a BYO TLS certificate. Null = auto self-signed.</summary>
    public string? TlsCertPath { get; set; }
    /// <summary>Gets or sets the password protecting the BYO TLS certificate.</summary>
    public string? TlsCertPassword { get; set; }
    /// <summary>Gets or sets the failure-flow mode (off, manual, or auto).</summary>
    public string FailureMode { get; set; } = "off";
    /// <summary>Gets or sets the simulator options derived from the command line.</summary>
    public SimulatorOptions Options { get; set; } = new();
}

/// <summary>Parses the simulator host command-line arguments.</summary>
public static class CommandLineOptions
{
    /// <summary>The usage/help text describing all supported flags.</summary>
    public const string Usage = """
        Intune Simulator
          --http-port <n>            (default 8080)
          --https-port <n>           (default 8443; MSAL authority must use https)
          --auth-password <s>        (default IntunePassw0rd!)
          --challenge-password <s>   (default derived from auth password)
          --tenant <s>               (default contoso.onmicrosoft.com)
          --app-id <s>               (default 0000000a-0000-0000-c000-000000000000)
          --advertised-base-url <s>  (override scheme://host advertised in discovery; needed behind IIS)
          --tls-cert <path.pfx>      (BYO TLS cert; default is auto self-signed)
          --tls-cert-password <s>
          --no-revocation            (disable PKI-connector revocation endpoints)
          --failure-mode <off|manual|auto>  (default off)
          --print-failure-doc        (print the failure-flow matrix and exit)
          --log-requests             (log each request to the console; on by default)
          --no-request-log           (disable per-request console logging)
          --help
        """;

    /// <summary>Parses the arguments into a <see cref="HostConfig"/>.</summary>
    /// <exception cref="ArgumentException">Thrown for unknown arguments, missing values, or <c>--help</c>.</exception>
    public static HostConfig Parse(string[] args)
    {
        var cfg = new HostConfig();
        var o = cfg.Options with { LogRequests = true };
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"Missing value for {a}");

            // Skip external/hosting args in --key=value form (e.g. WebApplicationFactory's --environment=Development,
            // --contentRoot=...). The simulator's own flags always use the space-separated "--key value" form.
            if (a.StartsWith("--", StringComparison.Ordinal) && a.Contains('=')) continue;

            switch (a)
            {
                case "--http-port": cfg.HttpPort = int.Parse(Next()); break;
                case "--https-port": cfg.HttpsPort = int.Parse(Next()); break;
                case "--auth-password": o = o with { AuthPassword = Next() }; break;
                case "--challenge-password": o = o with { ChallengePasswordOverride = Next() }; break;
                case "--tenant": o = o with { Tenant = Next() }; break;
                case "--app-id": o = o with { AppId = Next() }; break;
                case "--advertised-base-url": o = o with { AdvertisedBaseUrl = Next() }; break;
                case "--tls-cert": cfg.TlsCertPath = Next(); break;
                case "--tls-cert-password": cfg.TlsCertPassword = Next(); break;
                case "--no-revocation": o = o with { RevocationEnabled = false }; break;
                case "--failure-mode": cfg.FailureMode = Next().ToLowerInvariant(); break;
                case "--log-requests": o = o with { LogRequests = true }; break;
                case "--no-request-log": o = o with { LogRequests = false }; break;
                case "--print-failure-doc": break; // handled in Program before building
                case "--help": throw new ArgumentException(Usage);
                default: throw new ArgumentException($"Unknown argument: {a}\n{Usage}");
            }
        }
        cfg.Options = o;
        return cfg;
    }
}
