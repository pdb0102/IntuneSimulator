using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Server;
using ScepWright.Server.Host;
using Xunit;

namespace ScepWright.Tests;

public sealed class ScepCaHostTests {
    [Fact]
    public void Issued_chain_validates_against_ca() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        KeySpec spec;
        IScepKey key;
        X509Certificate2 ca_cert;
        X509Certificate2 leaf;
        X509Chain chain;
        bool built;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out key, out _);
        ca_cert = ca.CertificateBcl;
        leaf = new X509Certificate2(ca.Issue(((BcKey)key).KeyPair.Public, "CN=device-chain").GetEncoded());

        Assert.Contains(ca_cert.Extensions.OfType<X509BasicConstraintsExtension>(), e => e.CertificateAuthority);
        Assert.Contains(leaf.Extensions.OfType<X509BasicConstraintsExtension>(), e => !e.CertificateAuthority);
        Assert.Contains(leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>(),
            e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == "1.3.6.1.5.5.7.3.2"));   // clientAuth

        chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.Add(ca_cert);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        built = chain.Build(leaf);
        Assert.True(built, "leaf must chain to the CA (basicConstraints CA:TRUE required)");
    }

    [Fact]
    public void Run_rejects_unknown_flag() {
        StringWriter sw;
        int rc;

        sw = new StringWriter();
        rc = ServerCli.Run(new[] { "--bogus-flag", "x" }, sw);
        Assert.Equal(2, rc);
        Assert.Contains("unknown flag", sw.ToString());
    }

    [Fact]
    public void Run_export_ca_bad_path_errors_cleanly() {
        StringWriter sw;
        int rc;
        string data_dir;

        data_dir = Directory.CreateTempSubdirectory().FullName;
        sw = new StringWriter();
        rc = ServerCli.Run(new[] { "--data-dir", data_dir, "--export-ca", Path.Combine(data_dir, "no-such-subdir", "ca.der") }, sw);
        Assert.Equal(1, rc);
        Assert.Contains("could not write", sw.ToString());
    }

    [Fact]
    public void Help_lists_usage_and_untrusted_note() {
        string help;

        help = ServerCli.Help();
        Assert.Contains("scepca", help);
        Assert.Contains("UNTRUSTED", help);
        Assert.Contains("--export-ca", help);
    }

    // `scepca version` / `--version` must print a version and exit — not silently boot a server
    // (which scepclient/scepwright never do). Before the fix the positional was ignored and the server ran.
    [Theory]
    [InlineData("version")]
    [InlineData("--version")]
    public void Run_version_prints_and_exits(string arg) {
        StringWriter sw;
        int rc;

        sw = new StringWriter();
        rc = ServerCli.Run(new[] { arg }, sw);
        Assert.Equal(0, rc);
        Assert.Contains("scepca", sw.ToString());
        Assert.DoesNotContain("listening", sw.ToString());
    }

    // `scepca --export-ca --data-dir <dir>` used to write the CA to a file literally named "--data-dir"
    // (Opt returned args[i+1] blindly), and `--export-ca` as the last token booted a server. A value flag
    // whose argument is another flag or is missing must be rejected (exit 2), never consumed.
    [Fact]
    public void Run_export_ca_rejects_flag_as_filename() {
        string data_dir;
        StringWriter sw;
        int rc;

        data_dir = Directory.CreateTempSubdirectory().FullName;
        sw = new StringWriter();
        rc = ServerCli.Run(new[] { "--export-ca", "--data-dir", data_dir }, sw);
        Assert.Equal(2, rc);
        Assert.False(File.Exists("--data-dir"), "must not write a file named after the next flag");
        // --export-ca with no value at all must also be rejected, not boot a server.
        Assert.Equal(2, ServerCli.Run(new[] { "--export-ca" }, new StringWriter()));
    }

    [Fact]
    public void Run_help_returns_zero() {
        StringWriter sw;
        int rc;

        sw = new StringWriter();
        rc = ServerCli.Run(new[] { "--help" }, sw);
        Assert.Equal(0, rc);
        Assert.Contains("Usage", sw.ToString());
    }

    [Fact]
    public void Run_export_ca_writes_der() {
        string path;
        StringWriter sw;
        int rc;
        byte[] der;

        path = Path.Combine(Path.GetTempPath(), $"scepca-{Guid.NewGuid():N}.cer");
        sw = new StringWriter();
        try {
            rc = ServerCli.Run(new[] { "--export-ca", path }, sw);
            Assert.Equal(0, rc);
            der = File.ReadAllBytes(path);
            Assert.True(der.Length > 0);
        } finally {
            if (File.Exists(path)) { File.Delete(path); }
        }
    }

    // --export-ca must export the CA of the SELECTED --profile, not always rsa. They share the
    // CN=Test SCEP CA subject, so exporting the wrong one fails silently when you trust it.
    [Fact]
    public void Run_export_ca_honors_profile() {
        string data_dir;
        string rsa_path;
        string pq_path;
        StringWriter sw;

        data_dir = Directory.CreateTempSubdirectory().FullName;
        rsa_path = Path.Combine(data_dir, "rsa.der");
        pq_path = Path.Combine(data_dir, "mldsa.der");
        sw = new StringWriter();

        Assert.Equal(0, ServerCli.Run(new[] { "--data-dir", data_dir, "--profile", "rsa", "--export-ca", rsa_path }, sw));
        Assert.Equal(0, ServerCli.Run(new[] { "--data-dir", data_dir, "--profile", "mldsa-rsa", "--export-ca", pq_path }, sw));

        // Different profiles ⇒ different CA certificates.
        Assert.NotEqual(File.ReadAllBytes(rsa_path), File.ReadAllBytes(pq_path));
        // An unknown profile is rejected, not silently exported as rsa.
        Assert.Equal(2, ServerCli.Run(new[] { "--data-dir", data_dir, "--profile", "nope", "--export-ca", Path.Combine(data_dir, "x.der") }, new StringWriter()));
    }

    // A persist(encrypted) -> load "restart" through ServerCli must serve a STABLE CA: exporting the
    // rsa CA cert before and after a restart (with the right passphrase) yields identical bytes, proving
    // the encrypted key round-tripped rather than a fresh CA being generated.
    [Fact]
    public void Encrypt_keys_restart_serves_stable_ca() {
        string data_dir;
        string first_path;
        string second_path;
        StringWriter sw;

        data_dir = Directory.CreateTempSubdirectory().FullName;
        first_path = Path.Combine(data_dir, "ca-first.der");
        second_path = Path.Combine(data_dir, "ca-second.der");
        sw = new StringWriter();
        try {
            // First run: create + persist encrypted, export the rsa CA.
            Assert.Equal(0, ServerCli.Run(new[] { "--encrypt-keys", "--key-pass", "p@ss", "--data-dir", data_dir, "--profile", "rsa", "--export-ca", first_path }, sw));
            Assert.True(File.Exists(Path.Combine(data_dir, "ca", "rsa", "ca.key.pkcs8.enc")), "rsa CA key must be encrypted on disk");
            Assert.False(File.Exists(Path.Combine(data_dir, "ca", "rsa", "ca.key.pkcs8")), "no plaintext rsa CA key");

            // Restart: load encrypted with the same passphrase, export again.
            Assert.Equal(0, ServerCli.Run(new[] { "--key-pass", "p@ss", "--data-dir", data_dir, "--profile", "rsa", "--export-ca", second_path }, sw));

            Assert.Equal(File.ReadAllBytes(first_path), File.ReadAllBytes(second_path));
        } finally {
            if (Directory.Exists(data_dir)) { Directory.Delete(data_dir, true); }
        }
    }

    // Encrypted CA key on disk + no resolvable passphrase on a non-interactive console must FAIL with a
    // non-zero exit code and a clear message — never a hang, never a stack trace. Tests run with
    // CaKeyPassphrase.Interactive=false, so the console is never touched.
    [Fact]
    public void Restart_without_passphrase_on_encrypted_ca_fails_nonzero() {
        string data_dir;
        StringWriter sw;
        int rc;

        data_dir = Directory.CreateTempSubdirectory().FullName;
        sw = new StringWriter();
        try {
            Assert.Equal(0, ServerCli.Run(new[] { "--encrypt-keys", "--key-pass", "p@ss", "--data-dir", data_dir, "--profile", "rsa", "--export-ca", Path.Combine(data_dir, "x.der") }, sw));

            // No --key-pass, no env, non-interactive: must fail cleanly.
            rc = ServerCli.Run(new[] { "--data-dir", data_dir, "--profile", "rsa", "--export-ca", Path.Combine(data_dir, "y.der") }, sw);
            Assert.NotEqual(0, rc);
            Assert.Contains("passphrase", sw.ToString(), StringComparison.OrdinalIgnoreCase);
        } finally {
            if (Directory.Exists(data_dir)) { Directory.Delete(data_dir, true); }
        }
    }

    // A malformed PKIOperation POST (garbage / empty body that is not parseable CMS) must NOT 500 —
    // the code's own comment says a SCEP server must never 500. PeekMessageType (new CmsSignedData)
    // used to run above the try/catch, so garbage bytes threw and surfaced as HTTP 500.
    [Theory]
    [InlineData(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 })]
    [InlineData(new byte[0])]
    public async Task Malformed_pkioperation_post_returns_400_not_500(byte[] body) {
        ScepServerApp server;
        HttpClient client;
        HttpResponseMessage response;

        server = await ScepServerApp.StartAsync();
        client = new HttpClient();
        try {
            response = await client.PostAsync(server.ScepUrl, new ByteArrayContent(body));
            Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        } finally {
            client.Dispose();
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task Mapped_endpoints_serve_getcacaps_and_getcacert() {
        System.Collections.Generic.IReadOnlyDictionary<string, ScepCa> profiles;
        WebApplicationBuilder builder;
        WebApplication app;
        HttpClient client;
        string base_url;
        string caps;
        byte[] ca_der;
        byte[] profile_der;

        profiles = ScepServerApp.CreateDefaultProfiles();
        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();
        ScepServerApp.MapScepEndpoints(app, profiles["rsa"], profiles, () => "POSTPKIOperation\nSHA-256\nAES\n");
        await app.StartAsync();
        client = new HttpClient();
        try {
            base_url = System.Linq.Enumerable.First(app.Urls);

            caps = await client.GetStringAsync($"{base_url}/scep?operation=GetCACaps");
            Assert.Contains("SHA-256", caps);

            ca_der = await client.GetByteArrayAsync($"{base_url}/scep?operation=GetCACert");
            Assert.True(ca_der.Length > 0);

            profile_der = await client.GetByteArrayAsync($"{base_url}/scep/mlkem-encrypt?operation=GetCACert");
            Assert.True(profile_der.Length > 0);
        } finally {
            client.Dispose();
            await app.DisposeAsync();
        }
    }
}
