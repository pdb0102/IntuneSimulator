using System.Collections.Generic;

namespace ScepWright.Core.Testing;

/// <summary>A named, ordered sequence of CLI steps to run as a scenario.</summary>
public sealed class ScenarioFile {
    /// <summary>Gets or sets the scenario name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Gets or sets the ordered steps.</summary>
    public List<ScenarioStep> Steps { get; set; } = new();
}

/// <summary>A single scenario step: a command to run with arguments and an expected outcome.</summary>
public sealed class ScenarioStep {
    /// <summary>Gets or sets the step name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Gets or sets the command to run.</summary>
    public string Run { get; set; } = string.Empty;
    /// <summary>Gets or sets the server id the step targets, if any.</summary>
    public string? Server { get; set; }
    /// <summary>Gets or sets the command arguments.</summary>
    public Dictionary<string, string> Args { get; set; } = new();
    /// <summary>Gets or sets the expected outcome ("pass" or "fail"). Defaults to "pass".</summary>
    public string Expect { get; set; } = "pass";
}
