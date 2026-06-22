using IntuneSimulator.Core;
using IntuneSimulator.Core.Control;
using IntuneSimulator.Core.Failure;
using IntuneSimulator.Host;
using Microsoft.Extensions.DependencyInjection;

if (args.Contains("--print-failure-doc"))
{
    Console.WriteLine(FailureFlowDoc.Render());
    return;
}

HostConfig cfg;
try { cfg = CommandLineOptions.Parse(args); }
catch (ArgumentException ex) { Console.WriteLine(ex.Message); return; }

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddIntuneSimulator(cfg.Options);

var tls = TlsCertificateProvider.Resolve(cfg);
builder.WebHost.ConfigureKestrel(k =>
{
    k.ListenAnyIP(cfg.HttpPort);
    k.ListenAnyIP(cfg.HttpsPort, lo => lo.UseHttps(tls));
});

var app = builder.Build();

try
{
    File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "FAILURE-FLOW.md"),
        IntuneSimulator.Core.Failure.FailureFlowDoc.Render());
}
catch (IOException) { /* read-only deployment dir is fine */ }
catch (UnauthorizedAccessException) { /* ditto */ }

if (Enum.TryParse<FailureFlowMode>(cfg.FailureMode, true, out var fm))
    app.Services.GetRequiredService<FailureFlowEngine>().Mode = fm;

app.MapIntuneSimulator();

app.MapGet("/sim-cert.cer", () =>
{
    var path = Path.Combine(AppContext.BaseDirectory, "sim-tls", "sim-cert.cer");
    return File.Exists(path) ? Results.File(path, "application/pkix-cert", "sim-cert.cer") : Results.NotFound();
});

var state = app.Services.GetRequiredService<SimulatorState>();
var baseUrl = cfg.Options.AdvertisedBaseUrl ?? $"https://localhost:{cfg.HttpsPort}";
Console.WriteLine(InfoEndpoints.BuildBanner(baseUrl, state));
// The docs point users at the TLS cert's path + thumbprint as the trust anchor — print them so the
// banner actually carries what the docs say it does.
var tlsCertPath = !string.IsNullOrEmpty(cfg.TlsCertPath)
    ? cfg.TlsCertPath!
    : Path.Combine(AppContext.BaseDirectory, "sim-tls", "sim-cert.cer");
Console.WriteLine($"TLS cert (HTTPS:{cfg.HttpsPort}) : {tlsCertPath}");
Console.WriteLine($"TLS cert thumbprint   : {tls.Thumbprint}  (download: {baseUrl}/sim-cert.cer)");
if (cfg.Options.LogRequests)
    Console.WriteLine("Per-request logging: ON (disable with --no-request-log or POST /control {\"logRequests\":false})");
if (fm != FailureFlowMode.Off)
    Console.WriteLine($"Failure-flow mode: {fm}. See FAILURE-FLOW.md / POST /control for stepping.");

app.Run();

public partial class Program { }
