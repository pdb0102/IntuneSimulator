using IntuneSimulator.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace IntuneSimulator.Tests;

/// <summary>In-process host for the simulator with overridable options.</summary>
public sealed class SimulatorAppFactory : WebApplicationFactory<Program>
{
    private readonly SimulatorOptions _options;
    public SimulatorAppFactory(SimulatorOptions? options = null) => _options = options ?? new SimulatorOptions();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Replace the default options registered by Program with the test's options.
            var existing = services.Where(d => d.ServiceType == typeof(SimulatorOptions)).ToList();
            foreach (var d in existing) services.Remove(d);
            services.AddSingleton(_options);

            // Replace any existing SimulatorState with a fresh one built from the test options.
            var existingState = services.Where(d => d.ServiceType == typeof(SimulatorState)).ToList();
            foreach (var d in existingState) services.Remove(d);
            services.AddSingleton(new SimulatorState(_options));
        });
    }
}
