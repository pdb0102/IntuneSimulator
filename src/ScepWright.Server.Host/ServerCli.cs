using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using ScepWright.Server;

namespace ScepWright.Server.Host;

/// <summary>Parses the scepca command line and runs the self-contained SCEP test server.</summary>
public static class ServerCli {
    private const string HomeEnvVarName = "SCEPWRIGHT_HOME";

    /// <summary>Builds the scepca usage/help text.</summary>
    /// <param name="invocation">The command name to show in the help text.</param>
    public static string Help(string invocation = "scepca") {
        return string.Join('\n', new[] {
            $"{invocation} — a self-contained SCEP server (real certificates from a built-in, UNTRUSTED test CA).",
            "",
            $"Usage: {invocation} [--port <n>] [--caps \"<keywords>\"] [--profile <name>] [--pending] [--challenge <pw>] [--ndes-user <u> --ndes-password <p>]",
            $"       {invocation} --export-ca <path>     # write the default CA certificate (DER) and exit",
            $"       {invocation} version               # print the version and exit",
            "",
            "  --port <n>          Kestrel port (default 8090). Endpoints: /scep and /scep/<profile>.",
            "  --caps \"<kw>\"       advertised GetCACaps body (default \"POSTPKIOperation SHA-256 AES\").",
            "  --profile <name>    serve only this profile at /scep (default: all profiles at /scep/<name>).",
            "  --pending           every request returns PENDING (exercise client CertPoll).",
            "  --challenge <pw>    require this challenge password on PKCSReq.",
            "  --ndes-user <u> --ndes-password <p>   emulate NDES: serve the mscep_admin challenge page (Basic auth)",
            "                      that hands out one-time challenges the SCEP endpoint then accepts.",
            "  --export-ca <path>  write the CA cert (DER) for --profile (default rsa) to <path> and exit.",
            "  --data-dir <path>   persist CA state under <path>/ca (default ~/.scepwright/ca; or set $SCEPWRIGHT_HOME).",
            "  --encrypt-keys      encrypt CA/RA private keys at rest (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC).",
            "                      Persists ca.key.pkcs8.enc instead of ca.key.pkcs8 for newly created profiles.",
            "  --key-pass <pw>     CA key passphrase (to encrypt on create and to decrypt on restart).",
            "                      Precedence: --key-pass > $SCEPWRIGHT_CA_KEY_PASS > interactive hidden prompt.",
            "                      An encrypted CA key with no resolvable passphrase on a non-interactive",
            "                      console fails startup (non-zero exit) instead of prompting or hanging.",
            "",
            "Profiles: " + string.Join(", ", ScepServerApp.ProfileFactories().Keys.OrderBy(k => k)),
        });
    }

    /// <summary>Parses the server command line, starts (or exports) the SCEP CA, and returns a process exit code.</summary>
    /// <param name="args">The scepca command-line arguments.</param>
    /// <param name="output">The writer that receives status and error output.</param>
    /// <returns>A process exit code: 0 on success, non-zero on failure.</returns>
    public static int Run(string[] args, TextWriter output) {
        string? export_ca;
        string? caps;
        string? profile;
        string? challenge;
        bool pending;
        int port;
        Dictionary<string, ScepCa> profiles;
        ScepCa default_ca;
        string? ndes_user;
        string? ndes_password;
        bool encrypt_keys;
        string? key_pass;
        string ca_root;
        string? port_text;
        int p;

        if (HasFlag(args, "--help") || HasFlag(args, "-h")) {
            output.WriteLine(Help());
            return 0;
        }
        // version must short-circuit (before flag rejection) so `scepca version` / `--version` prints and
        // exits like scepclient/scepwright, instead of falling through and silently booting a server.
        if ((args.Length > 0 && args[0] == "version") || HasFlag(args, "--version")) {
            output.WriteLine($"scepca {VersionString()}");
            return 0;
        }
        if (!RejectUnknownFlags(args, output)) { return 2; }

        encrypt_keys = HasFlag(args, "--encrypt-keys");
        key_pass = CaKeyPassphrase.Resolve(Opt(args, "--key-pass"));
        ca_root = ResolveCaRoot(args);

        // An encrypted CA on disk requires a passphrase before we even attempt to load: fail with a
        // clear one-line message and a non-zero code rather than letting decryption throw, or hanging on
        // a non-interactive console. (--encrypt-keys on a fresh root also needs a passphrase to encrypt.)
        if (string.IsNullOrEmpty(key_pass) && (encrypt_keys || ScepServerApp.HasEncryptedKeys(ca_root))) {
            output.WriteLine("CA key passphrase required (encrypted keys at rest): pass --key-pass <pw> or set $SCEPWRIGHT_CA_KEY_PASS.");
            return 2;
        }

        try {
            profiles = ScepServerApp.LoadOrCreateProfiles(ca_root, key_pass, encrypt_keys);
        } catch (ScepWright.Server.CaKeyProtectionException ex) {
            output.WriteLine($"failed to load CA keys: {ex.Message}");
            return 2;
        }
        profile = Opt(args, "--profile");
        if (profile != null && !profiles.ContainsKey(profile)) {
            output.WriteLine($"unknown profile '{profile}'. Known: {string.Join(", ", profiles.Keys.OrderBy(k => k))}");
            return 2;
        }
        export_ca = Opt(args, "--export-ca");
        if (export_ca != null) {
            string export_profile;

            // Export the CA the user is actually serving: honor --profile (every profile has its OWN CA;
            // they share the CN=Test SCEP CA subject, so exporting the wrong one fails silently downstream).
            export_profile = profile ?? "rsa";
            try {
                File.WriteAllBytes(export_ca, profiles[export_profile].CertificateBcl.RawData);
            } catch (Exception ex) {
                output.WriteLine($"could not write CA certificate to '{export_ca}': {ex.Message}");
                return 1;
            }
            output.WriteLine($"wrote '{export_profile}' CA certificate to {Path.GetFullPath(export_ca)}");
            return 0;
        }

        caps = Opt(args, "--caps");
        challenge = Opt(args, "--challenge");
        pending = HasFlag(args, "--pending");
        ndes_user = Opt(args, "--ndes-user");
        ndes_password = Opt(args, "--ndes-password");
        if ((ndes_user != null) != (ndes_password != null)) {
            output.WriteLine("--ndes-user and --ndes-password must be given together");
            return 2;
        }
        port_text = Opt(args, "--port");
        if (port_text != null && !int.TryParse(port_text, out _)) {
            output.WriteLine($"invalid --port '{port_text}' (expected a number)");
            return 2;
        }
        port = int.TryParse(port_text, out p) ? p : 8090;

        default_ca = profile != null ? profiles[profile] : profiles["rsa"];
        foreach (ScepCa ca in profiles.Values) {
            ca.PendingMode = pending;
            ca.ExpectedChallenge = challenge;
        }
        default_ca.PendingMode = pending;
        default_ca.ExpectedChallenge = challenge;
        // NDES emulation applies to the whole server: every profile issues+accepts its own one-time
        // challenge, and its mscep_admin page is served parallel to its SCEP endpoint.
        if (ndes_user != null) {
            foreach (ScepCa ca in profiles.Values) { ca.NdesMode = true; }
        }

        return Serve(port, default_ca, profiles, caps, ndes_user, ndes_password, !string.IsNullOrEmpty(key_pass), output);
    }

    private static int Serve(int port, ScepCa default_ca, IReadOnlyDictionary<string, ScepCa> profiles, string? caps, string? ndes_user, string? ndes_password, bool keys_encrypted, TextWriter output) {
        WebApplicationBuilder builder;
        WebApplication app;
        string caps_body;

        caps_body = caps != null ? caps.Replace(' ', '\n') + "\n" : "POSTPKIOperation\nSHA-256\nAES\n";

        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
        app = builder.Build();
        ScepServerApp.MapScepEndpoints(app, default_ca, profiles, () => caps_body);
        if (ndes_user != null && ndes_password != null) {
            ScepServerApp.MapNdesAdmin(app, default_ca, ndes_user, ndes_password, profiles);
        }

        output.WriteLine($"scepca listening on http://0.0.0.0:{port}  (SCEP: /scep, /scep/<profile>)");
        if (ndes_user != null && ndes_password != null) {
            output.WriteLine($"NDES admin: /mscep_admin/ (HTTP Basic auth) — hands out one-time challenges the SCEP endpoint accepts.");
        }
        if (keys_encrypted) {
            output.WriteLine("CA private key is encrypted at rest (PBES2 PBKDF2-HMAC-SHA256 / AES-256-CBC).");
        }
        output.WriteLine("CA is UNTRUSTED (built-in test CA). Export it with --export-ca to trust it in a client.");
        app.Run();
        return 0;
    }

    internal static string ResolveCaRoot(string[] args) {
        return ResolveCaRoot(args, Environment.GetEnvironmentVariable(HomeEnvVarName));
    }

    internal static string ResolveCaRoot(string[] args, string? env_home) {
        string? data_dir;
        string home;

        data_dir = Opt(args, "--data-dir");
        if (!string.IsNullOrEmpty(data_dir)) { return Path.Combine(data_dir, "ca"); }
        if (!string.IsNullOrEmpty(env_home)) { return Path.Combine(env_home, "ca"); }
        home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".scepwright", "ca");
    }

    // The InformationalVersion stamped by Directory.Build.props (e.g. "1.0.0"), matching scepclient/scepwright.
    private static string VersionString() {
        System.Reflection.Assembly asm;
        System.Reflection.AssemblyInformationalVersionAttribute? info;

        asm = typeof(ServerCli).Assembly;
        info = System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm);
        return string.IsNullOrEmpty(info?.InformationalVersion) ? (asm.GetName().Version?.ToString() ?? "unknown") : info!.InformationalVersion;
    }

    private static string? Opt(string[] args, string name) {
        int i;

        for (i = 0; i < args.Length - 1; i++) {
            if (args[i] == name) { return args[i + 1]; }
        }
        return null;
    }

    private static bool HasFlag(string[] args, string flag) {
        int i;

        for (i = 0; i < args.Length; i++) {
            if (args[i] == flag) { return true; }
        }
        return false;
    }

    // Rejects any flag-looking token (starts with '-') that is not a known scepca option, so typos
    // surface instead of being silently ignored.
    private static bool RejectUnknownFlags(string[] args, TextWriter output) {
        HashSet<string> value_flags;
        HashSet<string> bool_flags;
        int i;

        value_flags = new HashSet<string> { "--port", "--caps", "--profile", "--challenge", "--export-ca", "--data-dir", "--ndes-user", "--ndes-password", "--key-pass" };
        bool_flags = new HashSet<string> { "--pending", "--help", "-h", "--encrypt-keys" };

        for (i = 0; i < args.Length; i++) {
            string token;

            token = args[i];
            if (token.Length == 0 || token[0] != '-') { continue; }
            if (value_flags.Contains(token)) {
                // A value flag's argument must be present and must not be another flag, or Opt() would
                // blindly consume it (e.g. `--export-ca --data-dir x` writing a file named "--data-dir").
                if (i + 1 >= args.Length || (args[i + 1].Length > 0 && args[i + 1][0] == '-')) {
                    output.WriteLine($"flag '{token}' requires a value (run with --help for usage)");
                    return false;
                }
                i++;
                continue;
            }
            if (bool_flags.Contains(token)) { continue; }

            output.WriteLine($"unknown flag '{token}' (run with --help for usage)");
            return false;
        }
        return true;
    }
}
