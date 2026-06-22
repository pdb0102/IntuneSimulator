using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace ScepWright.Server;

/// <summary>
/// A fake SCEP server. Besides the default <c>/scep</c> endpoint it also stands up a set of ready-to-use
/// per-profile endpoints at <c>/scep/&lt;profile&gt;</c>, each backed by its own <see cref="ScepCa"/> with
/// a specific signing/encryption certificate shape — so a real SCEP client (or a scripted test) can
/// exercise every recipient combination just by starting the server and hitting the right URL.
/// </summary>
public sealed class ScepServerApp : IAsyncDisposable {
    private readonly WebApplication _app;
    private string _base_url = "http://127.0.0.1:0";

    /// <summary>Gets the absolute URL of the default <c>/scep</c> endpoint.</summary>
    public Uri ScepUrl { get; private set; }
    /// <summary>Gets the CA backing the default endpoint.</summary>
    public ScepCa Ca { get; }
    /// <summary>Gets the GetCACaps response body the server returns.</summary>
    public string CaCapsBody { get; init; } = "POSTPKIOperation\nSHA-256\nAES\n";

    private ScepServerApp(WebApplication app, ScepCa ca) {
        _app = app;
        Ca = ca;
        ScepUrl = new Uri("http://127.0.0.1/scep");
    }

    /// <summary>Starts the server on an ephemeral local port with a freshly created default CA.</summary>
    public static async Task<ScepServerApp> StartAsync() => await StartAsync(null);

    /// <summary>Starts the server on an ephemeral local port.</summary>
    /// <param name="ca_override">The CA to back the default endpoint, or <c>null</c> to create a default one.</param>
    public static async Task<ScepServerApp> StartAsync(ScepCa? ca_override) {
        WebApplicationBuilder builder;
        WebApplication app;
        ScepCa ca;
        Dictionary<string, ScepCa> profiles;
        ScepServerApp self;
        string base_url;

        ca = ca_override ?? ScepCa.Create();
        profiles = CreateDefaultProfiles();

        builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        app = builder.Build();
        self = new ScepServerApp(app, ca);

        ScepServerApp.MapScepEndpoints(app, self.Ca, profiles, () => self.CaCapsBody);

        await app.StartAsync();

        base_url = app.Urls.First();
        self._base_url = base_url;
        self.ScepUrl = new Uri(new Uri(base_url), "/scep");
        return self;
    }

    /// <summary>Returns the absolute URL of the named per-profile endpoint.</summary>
    /// <param name="name">The profile name (e.g. <c>rsa-split</c>, <c>mlkem-encrypt</c>).</param>
    public Uri ProfileUrl(string name) => new Uri(new Uri(_base_url), $"/scep/{name}");

    /// <summary>Returns the factory delegates for the built-in per-profile CAs, keyed by profile name.</summary>
    public static Dictionary<string, Func<ScepCa>> ProfileFactories() {
        // Each profile gets a DISTINCT CA subject DN ("Test SCEP CA — <profile>") so a subject-keyed
        // trust store doesn't collapse every profile onto one CN (and so an exported CA is identifiable).
        return new Dictionary<string, Func<ScepCa>> {
            { "rsa", () => ScepCa.Create("rsa", "Test SCEP CA — rsa") },
            { "rsa-split", () => ScepCa.CreateWithRaEncryption("rsa", "rsa", "Test SCEP CA — rsa-split") },
            { "ec-encrypt", () => ScepCa.CreateWithRaEncryption("ec", "rsa", "Test SCEP CA — ec-encrypt") },
            { "ec-dual", () => ScepCa.Create("ec", "Test SCEP CA — ec-dual") },
            { "ecdsa-rsa", () => ScepCa.CreateWithRaEncryption("rsa", "ec", "Test SCEP CA — ecdsa-rsa") },
            { "mldsa-rsa", () => ScepCa.CreateWithRaEncryption("rsa", "ml-dsa", "Test SCEP CA — mldsa-rsa") },
            { "mldsa-only", () => ScepCa.Create("ml-dsa", "Test SCEP CA — mldsa-only") },
            { "slhdsa-rsa", () => ScepCa.CreateWithRaEncryption("rsa", "slh-dsa", "Test SCEP CA — slhdsa-rsa") },
            { "mlkem-encrypt", () => ScepCa.CreateWithRaEncryption("ml-kem", "rsa", "Test SCEP CA — mlkem-encrypt") },
            { "mldsa-mlkem", () => ScepCa.CreateWithRaEncryption("ml-kem", "ml-dsa", "Test SCEP CA — mldsa-mlkem") },
            { "signing-only", () => ScepCa.CreateSigningOnly("Test SCEP CA — signing-only") },
        };
    }

    /// <summary>Creates a fresh instance of every built-in per-profile CA, keyed by profile name.</summary>
    public static Dictionary<string, ScepCa> CreateDefaultProfiles() {
        Dictionary<string, ScepCa> result;

        result = new Dictionary<string, ScepCa>();
        foreach (KeyValuePair<string, Func<ScepCa>> entry in ProfileFactories()) {
            result[entry.Key] = entry.Value();
        }
        return result;
    }

    /// <summary>Loads each per-profile CA from the root directory, creating and persisting any that are missing, with plaintext keys.</summary>
    /// <param name="ca_root">The root directory holding one subdirectory per profile.</param>
    public static Dictionary<string, ScepCa> LoadOrCreateProfiles(string ca_root) {
        return LoadOrCreateProfiles(ca_root, null, false);
    }

    /// <summary>Loads each per-profile CA from the root directory, creating and persisting any that are missing.</summary>
    /// <param name="ca_root">The root directory holding one subdirectory per profile.</param>
    /// <param name="passphrase">When non-empty, decrypts existing encrypted keys on load.</param>
    /// <param name="encrypt_keys">When set, encrypts the keys of any newly created profile on persist (using <paramref name="passphrase"/>).</param>
    /// <exception cref="CaKeyProtectionException">A persisted profile is encrypted and the passphrase is wrong or missing.</exception>
    public static Dictionary<string, ScepCa> LoadOrCreateProfiles(string ca_root, string? passphrase, bool encrypt_keys) {
        Dictionary<string, ScepCa> result;

        result = new Dictionary<string, ScepCa>();
        foreach (KeyValuePair<string, Func<ScepCa>> entry in ProfileFactories()) {
            string dir;
            ScepCa ca;

            dir = Path.Combine(ca_root, entry.Key);
            if (File.Exists(Path.Combine(dir, "ca.cert.der"))) {
                ca = ScepCa.LoadFrom(dir, passphrase);
            } else {
                ca = entry.Value();
                try { ca.Persist(dir, encrypt_keys ? passphrase : null); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
            result[entry.Key] = ca;
        }
        return result;
    }

    /// <summary>
    /// Returns <c>true</c> when the persisted CA root holds at least one encrypted profile key
    /// (<c>ca.key.pkcs8.enc</c>) — the host uses this to decide whether a passphrase is required before a load.
    /// </summary>
    /// <param name="ca_root">The root directory holding one subdirectory per profile.</param>
    public static bool HasEncryptedKeys(string ca_root) {
        foreach (string key in ProfileFactories().Keys) {
            if (File.Exists(Path.Combine(ca_root, key, "ca.key.pkcs8.enc"))) {
                return true;
            }
        }
        return false;
    }

    /// <summary>Maps the default <c>/scep</c> GET/POST endpoints plus a GET/POST pair for each per-profile CA.</summary>
    /// <param name="app">The web application to add routes to.</param>
    /// <param name="default_ca">The CA backing the default <c>/scep</c> endpoint.</param>
    /// <param name="profiles">The per-profile CAs to expose under <c>/scep/&lt;profile&gt;</c>.</param>
    /// <param name="caps_body">A callback returning the GetCACaps response body.</param>
    public static void MapScepEndpoints(WebApplication app, ScepCa default_ca, IReadOnlyDictionary<string, ScepCa> profiles, Func<string> caps_body) {
        app.MapGet("/scep", (HttpContext ctx) => HandleGet(default_ca, caps_body(), ctx));
        app.MapPost("/scep", (HttpContext ctx) => HandlePost(default_ca, ctx));

        foreach (KeyValuePair<string, ScepCa> profile in profiles) {
            ScepCa profile_ca;

            profile_ca = profile.Value;
            app.MapGet($"/scep/{profile.Key}", (HttpContext ctx) => HandleGet(profile_ca, caps_body(), ctx));
            app.MapPost($"/scep/{profile.Key}", (HttpContext ctx) => HandlePost(profile_ca, ctx));
        }
    }

    /// <summary>
    /// Maps the Microsoft <c>mscep_admin</c> NDES enrollment-challenge page (Basic-auth gated) so
    /// <c>scepclient --ndes</c> can be exercised end to end. Each GET hands out a fresh one-time challenge
    /// the SCEP PKIOperation then accepts. The page is served parallel to every SCEP endpoint (each
    /// carrying its own profile's CA thumbprint), plus the classic fixed NDES paths for the default CA.
    /// </summary>
    /// <param name="app">The web application to add routes to.</param>
    /// <param name="default_ca">The CA backing the default and fixed NDES paths.</param>
    /// <param name="user">The Basic-auth username required to view the challenge page.</param>
    /// <param name="password">The Basic-auth password required to view the challenge page.</param>
    /// <param name="profiles">The per-profile CAs to expose <c>mscep_admin</c> pages for, or <c>null</c> for none.</param>
    public static void MapNdesAdmin(WebApplication app, ScepCa default_ca, string user, string password,
                                    IReadOnlyDictionary<string, ScepCa>? profiles = null) {
        MapNdesAdminAt(app, "/mscep_admin", default_ca, user, password);
        MapNdesAdminAt(app, "/CertSrv/mscep_admin", default_ca, user, password);
        // Parallel to the default /scep endpoint, and to each per-profile /scep/<profile> endpoint.
        MapNdesAdminAt(app, "/scep/mscep_admin", default_ca, user, password);
        if (profiles is not null) {
            foreach (KeyValuePair<string, ScepCa> profile in profiles) {
                MapNdesAdminAt(app, $"/scep/{profile.Key}/mscep_admin", profile.Value, user, password);
            }
        }
    }

    private static void MapNdesAdminAt(WebApplication app, string base_path, ScepCa ca, string user, string password) {
        app.MapGet(base_path, (HttpContext ctx) => HandleNdesAdmin(ca, user, password, ctx));
        app.MapGet(base_path + "/{**rest}", (HttpContext ctx) => HandleNdesAdmin(ca, user, password, ctx));
    }

    private static async Task HandleNdesAdmin(ScepCa ca, string user, string password, HttpContext ctx) {
        if (!BasicAuthMatches(ctx, user, password)) {
            ctx.Response.StatusCode = 401;
            ctx.Response.Headers["WWW-Authenticate"] = "Basic realm=\"mscep_admin\"";
            return;
        }
        ctx.Response.ContentType = "text/html; charset=UTF-8";
        await ctx.Response.WriteAsync(string.Format(NdesAdminHtml, ca.CertificateBcl.Thumbprint, ca.IssueNdesChallenge(), 60));
    }

    private static bool BasicAuthMatches(HttpContext ctx, string user, string password) {
        string header;
        string expected;

        header = ctx.Request.Headers["Authorization"].ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) {
            return false;
        }
        expected = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{user}:{password}"));
        return string.Equals(header.Substring("Basic ".Length).Trim(), expected, StringComparison.Ordinal);
    }

    private const string NdesAdminHtml = """<HTML><Head><Meta HTTP-Equiv="Content-Type" Content="text/html; charset=UTF-8"><Title>Network Device Enrollment Service</Title></Head><Body BgColor=#FFFFFF><Font ID=locPageFont Face="Arial"><Table Border=0 CellSpacing=0 CellPadding=4 Width=100% BgColor=#008080><TR><TD><Font ID=locPageTitleFont Face="Arial" Size=-1 Color=#FFFFFF><LocID ID=locMSCertSrv>Network Device Enrollment Service</LocID></Font></TD></TR></Table><P ID=locPageTitle> Network Device Enrollment Service allows you to obtain certificates for routers or other network devices using the Simple Certificate Enrollment Protocol (SCEP). </P><P> To complete certificate enrollment for your network device you will need the following information: <P> The thumbprint (hash value) for the CA certificate is: <B> {0} </B> <P> The enrollment challenge password is: <B> {1} </B> <P> This password can be used only once and will expire within {2} minutes. <P> Each enrollment requires a new challenge password. You can refresh this web page to obtain a new challenge password. </P> <P ID=locPageDesc> For more information see  <A HREF=http://go.microsoft.com/fwlink/?LinkId=67852>Using Network Device Enrollment Service </A>. </P> <P></Font></Body></HTML>""";

    private static async Task HandleGet(ScepCa ca, string caps_body, HttpContext ctx) {
        string op;
        byte[] bundle;

        op = ctx.Request.Query["operation"].ToString();
        if (op == "GetCACaps") { await ctx.Response.WriteAsync(caps_body); return; }
        if (op == "GetCACert") {
            bundle = ca.BuildCaCertBundleDer();
            ctx.Response.ContentType = ca.EncryptionCert is null ? "application/x-x509-ca-cert" : "application/x-x509-ca-ra-cert";
            await ctx.Response.Body.WriteAsync(bundle);
            return;
        }
        ctx.Response.StatusCode = 400;
    }

    private static async Task HandlePost(ScepCa ca, HttpContext ctx) {
        MemoryStream ms;
        byte[] request_der;
        byte[] response;
        string message_type;

        ms = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(ms);
        request_der = ms.ToArray();

        try {
            // PeekMessageType (new CmsSignedData) must stay inside the guard: a garbage or empty body
            // throws while parsing the CMS, and a SCEP server must never 500 on a request it can't parse.
            message_type = ca.PeekMessageType(request_der);
            if (message_type == "21") { response = ca.HandleGetCert(request_der); }
            else if (message_type == "22") { response = ca.HandleGetCrl(request_der); }
            else if (message_type == "20") { response = ca.HandlePoll(request_der); }
            else { response = ca.HandlePkiOperation(request_der); }
        } catch (System.Exception) {
            // A SCEP server must never 500 on a request it can't satisfy. Known cases (e.g. a
            // signature-only renewal recipient) already return a signed failInfo; this is the net for
            // anything unforeseen — a clean 400 the client surfaces as a transport error, not a crash.
            ctx.Response.StatusCode = 400;
            return;
        }

        ctx.Response.ContentType = "application/x-pki-message";
        await ctx.Response.Body.WriteAsync(response);
    }

    /// <summary>Stops and disposes the underlying web application.</summary>
    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
