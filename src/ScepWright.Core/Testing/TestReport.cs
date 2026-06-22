using System.Collections.Generic;
using System.Linq;

namespace ScepWright.Core.Testing;

/// <summary>The aggregated results of a test/compliance run, plus run attribution and footprint.</summary>
public sealed class TestReport {
    /// <summary>Gets the server identifier the run targeted.</summary>
    public string ServerId { get; init; } = string.Empty;
    /// <summary>Gets the suite/mode that was run.</summary>
    public string Mode { get; init; } = string.Empty;
    /// <summary>Gets the individual check results.</summary>
    public List<CheckResult> Results { get; } = new();
    /// <summary>Gets the real certificates this run caused the CA to issue, for cleanup / revocation.</summary>
    public List<IssuedCert> Footprint { get; } = new();
    /// <summary>Gets or sets the total wall-clock time of the run.</summary>
    public System.TimeSpan TotalElapsed { get; set; }

    /// <summary>Gets or sets when the report was generated (audit attribution).</summary>
    public System.DateTime GeneratedUtc { get; set; }
    /// <summary>Gets or sets the tool version that produced the report.</summary>
    public string ToolVersion { get; set; } = string.Empty;
    /// <summary>Gets or sets the target URL exercised.</summary>
    public string TargetUrl { get; set; } = string.Empty;
    /// <summary>Gets or sets the CA certificate thumbprint.</summary>
    public string CaThumbprint { get; set; } = string.Empty;

    /// <summary>Gets the number of passed checks.</summary>
    public int Passed => Results.Count(r => r.Outcome == CheckOutcome.Passed);
    /// <summary>Gets the number of failed checks.</summary>
    public int Failed => Results.Count(r => r.Outcome == CheckOutcome.Failed);
    /// <summary>Gets the number of skipped checks.</summary>
    public int Skipped => Results.Count(r => r.Outcome == CheckOutcome.Skipped);
    /// <summary>Gets the number of leniency findings.</summary>
    public int Findings => Results.Count(r => r.Outcome == CheckOutcome.Finding);
}
