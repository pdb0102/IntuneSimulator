using IntuneSimulator.Core.Auth;
using IntuneSimulator.Core.Control;
using IntuneSimulator.Core.Failure;
using IntuneSimulator.Core.Graph;
using IntuneSimulator.Core.Recording;
using IntuneSimulator.Core.Revocation;
using IntuneSimulator.Core.Scep;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace IntuneSimulator.Core;

public static class Endpoints
{
    /// <summary>Registers simulator services. Call before building the app.</summary>
    public static IServiceCollection AddIntuneSimulator(this IServiceCollection services, SimulatorOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<SimulatorState>();
        services.AddSingleton<IntuneSimulator.Core.Signing.TokenSigningKey>();
        services.AddSingleton<IntuneSimulator.Core.Auth.ClientCredentialValidator>();
        services.AddSingleton<RequestRecorder>();
        services.AddSingleton<IntuneSimulator.Core.Recording.RequestLogSink>();
        services.AddSingleton<FailureFlowEngine>();
        return services;
    }

    /// <summary>Maps all simulator endpoints. Call after building the app.</summary>
    public static WebApplication MapIntuneSimulator(this WebApplication app)
    {
        app.UseMiddleware<IntuneSimulator.Core.Recording.RequestLogMiddleware>();
        app.UseMiddleware<IntuneSimulator.Core.Failure.FailureFlowMiddleware>();
        app.MapAadEndpoints();
        app.MapGraphEndpoints();
        app.MapScepEndpoints();
        var opts = app.Services.GetRequiredService<SimulatorOptions>();
        if (opts.RevocationEnabled) app.MapRevocationEndpoints();
        app.MapInfoEndpoints();
        app.MapChallengeEndpoints();
        app.MapControlEndpoints();
        return app;
    }
}
