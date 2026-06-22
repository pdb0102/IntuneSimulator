using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ScepWright.Core;
using ScepWright.Core.Challenge;
using ScepWright.Core.Storage;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

// scepca's NDES emulation: the mscep_admin page (Basic-auth gated) hands out a one-time challenge
// that the SCEP PKIOperation then accepts — so `scepclient --ndes` is testable end to end.
public sealed class NdesTests {
    [Fact]
    public async Task Ndes_admin_gates_on_basic_auth_and_issues_a_usable_one_time_challenge() {
        System.Collections.Generic.IReadOnlyDictionary<string, ScepCa> profiles;
        ScepCa ca;
        WebApplicationBuilder builder;
        WebApplication app;
        HttpClient http;
        string base_url;
        HttpResponseMessage no_auth;
        NdesChallengeSource source;
        string challenge;
        string error;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        ScepResult<EnrollOutcome> issued;
        IScepKey key2;
        ScepResult<EnrollOutcome> reused;
        IScepKey key3;
        ScepResult<EnrollOutcome> bogus;

        profiles = ScepServerApp.CreateDefaultProfiles();
        ca = profiles["rsa"];
        ca.NdesMode = true;

        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();
        ScepServerApp.MapScepEndpoints(app, ca, profiles, () => "POSTPKIOperation\nSHA-256\nAES\n");
        ScepServerApp.MapNdesAdmin(app, ca, "ndesuser", "ndespass");
        await app.StartAsync();

        http = new HttpClient();
        try {
            base_url = System.Linq.Enumerable.First(app.Urls);

            // No / wrong Basic auth -> 401.
            no_auth = await http.GetAsync($"{base_url}/mscep_admin/");
            Assert.Equal(HttpStatusCode.Unauthorized, no_auth.StatusCode);

            // The client's own NDES scraper pulls a challenge from the page with correct credentials.
            source = new NdesChallengeSource(http, $"{base_url}/mscep_admin/", "ndesuser", "ndespass");
            Assert.True(source.TryGet(out challenge, out error), error);
            Assert.False(string.IsNullOrEmpty(challenge));

            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "ndes", Url = new Uri($"{base_url}/scep"), PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;

            // The issued challenge is accepted by the SCEP endpoint.
            KeySpec.Parse("rsa:2048", out spec, out _);
            crypto.GenerateKey(spec, out key, out _);
            issued = client.GetNewCertificate(new EnrollRequest { Subject = "CN=ndes-dev", Key = key, ChallengePassword = challenge }, new CertStore(root), new UseRecordLog(root));
            Assert.True(issued.IsOk, $"{issued.Status} {issued.Error}");

            // One-time: replaying the same challenge is now rejected.
            crypto.GenerateKey(spec, out key2, out _);
            reused = client.GetNewCertificate(new EnrollRequest { Subject = "CN=ndes-replay", Key = key2, ChallengePassword = challenge }, new CertStore(root), new UseRecordLog(root));
            Assert.False(reused.IsOk);

            // A never-issued challenge is rejected.
            crypto.GenerateKey(spec, out key3, out _);
            bogus = client.GetNewCertificate(new EnrollRequest { Subject = "CN=ndes-bogus", Key = key3, ChallengePassword = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF" }, new CertStore(root), new UseRecordLog(root));
            Assert.False(bogus.IsOk);
        } finally {
            http.Dispose();
            await app.DisposeAsync();
        }
    }

    // The mscep_admin page is served PARALLEL to each SCEP endpoint (…/scep/<profile>/mscep_admin/),
    // each carrying its own profile's CA thumbprint — so NdesAdminUrl.Derive(<profile-url>) resolves it
    // with no explicit --ndes-admin-url, and the bundled scepclient --ndes round-trip works per profile.
    [Fact]
    public async Task Ndes_admin_is_served_parallel_to_each_profile_endpoint() {
        System.Collections.Generic.Dictionary<string, ScepCa> profiles;
        WebApplicationBuilder builder;
        WebApplication app;
        HttpClient http;
        string base_url;
        string mldsa_url;
        string mldsa_admin;
        NdesChallengeSource source;
        string challenge;
        string error;
        HttpResponseMessage page;
        string body;
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;
        KeySpec spec;
        IScepKey key;
        ScepResult<EnrollOutcome> issued;

        profiles = ScepServerApp.CreateDefaultProfiles();
        foreach (ScepCa profile_ca in profiles.Values) { profile_ca.NdesMode = true; }

        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();
        ScepServerApp.MapScepEndpoints(app, profiles["rsa"], profiles, () => "POSTPKIOperation\nSHA-256\nAES\n");
        ScepServerApp.MapNdesAdmin(app, profiles["rsa"], "ndesuser", "ndespass", profiles);
        await app.StartAsync();

        http = new HttpClient();
        try {
            base_url = System.Linq.Enumerable.First(app.Urls);
            mldsa_url = $"{base_url}/scep/mldsa-rsa";

            // Derive resolves the admin URL parallel to the profile endpoint (no explicit override).
            mldsa_admin = NdesAdminUrl.Derive(mldsa_url);
            Assert.Equal($"{mldsa_url}/mscep_admin/", mldsa_admin);

            // The page carries THIS profile's CA thumbprint (cert-in-path), not the default CA's.
            page = await SendBasic(http, mldsa_admin, "ndesuser", "ndespass");
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            body = await page.Content.ReadAsStringAsync();
            Assert.Contains(profiles["mldsa-rsa"].CertificateBcl.Thumbprint, body, System.StringComparison.OrdinalIgnoreCase);

            // Full round-trip: scrape the challenge and enroll against the same profile endpoint.
            source = new NdesChallengeSource(http, mldsa_admin, "ndesuser", "ndespass");
            Assert.True(source.TryGet(out challenge, out error), error);

            crypto = new BouncyCastleScepCrypto();
            ScepClient.Create(new ServerConfig { Id = "ndes-prof", Url = new Uri(mldsa_url), PreferPost = true }, crypto, handler: null, out client, out _);
            root = Directory.CreateTempSubdirectory().FullName;
            KeySpec.Parse("rsa:2048", out spec, out _);
            crypto.GenerateKey(spec, out key, out _);
            issued = client.GetNewCertificate(new EnrollRequest { Subject = "CN=ndes-prof-dev", Key = key, ChallengePassword = challenge }, new CertStore(root), new UseRecordLog(root));
            Assert.True(issued.IsOk, $"{issued.Status} {issued.Error}");
        } finally {
            http.Dispose();
            await app.DisposeAsync();
        }
    }

    private static async Task<HttpResponseMessage> SendBasic(HttpClient http, string url, string user, string password) {
        HttpRequestMessage req;

        req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Add("Authorization", "Basic " + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{user}:{password}")));
        return await http.SendAsync(req);
    }
}
