using System.Text;
using ScepWright.Core.Testing;

namespace ScepWright.Core.Reporting;

/// <summary>Renders a test report as a human-readable console summary.</summary>
public static class ConsoleSummary {
    /// <summary>Formats the report as plain text for the console.</summary>
    public static string Emit(TestReport report) {
        StringBuilder sb;

        sb = new StringBuilder();
        sb.AppendLine($"SCEP test run — {report.ServerId} — {report.Mode}          {report.TotalElapsed.TotalSeconds:0.0}s");
        if (report.GeneratedUtc != default) {
            sb.AppendLine($"  {report.GeneratedUtc:u} · {report.TargetUrl} · scepwright {report.ToolVersion} · CA {report.CaThumbprint}");
        }
        sb.AppendLine($"  PASSED   {report.Passed}");
        sb.AppendLine($"  FAILED   {report.Failed}");
        sb.AppendLine($"  SKIPPED  {report.Skipped}");
        sb.AppendLine($"  FINDINGS {report.Findings}");

        if (report.Failed > 0) {
            sb.AppendLine();
            sb.AppendLine("FAILED:");
            foreach (CheckResult r in report.Results) {
                if (r.Outcome == CheckOutcome.Failed) {
                    // Only show the failInfo expectation when it carries information; otherwise it reads
                    // as the confusing "expected None, got None".
                    if (r.Expected != ScepWright.Crypto.FailInfo.None || r.Got != ScepWright.Crypto.FailInfo.None) {
                        sb.AppendLine($"  ✗ {r.Name} → expected failInfo {r.Expected}, got {r.Got}");
                    } else {
                        sb.AppendLine($"  ✗ {r.Name}");
                    }
                    sb.AppendLine($"      {r.Why}  ({r.RfcReference})");
                }
            }
        }
        if (report.Findings > 0) {
            sb.AppendLine();
            sb.AppendLine("FINDINGS:");
            foreach (CheckResult r in report.Results) {
                if (r.Outcome == CheckOutcome.Finding) {
                    sb.AppendLine($"  • {r.Name}: {r.Why}");
                }
            }
        }
        if (report.Footprint.Count > 0) {
            sb.AppendLine();
            sb.AppendLine($"FOOTPRINT ({report.Footprint.Count} real certificate(s) issued — revoke/clean up):");
            foreach (IssuedCert c in report.Footprint) {
                sb.AppendLine($"  • serial {c.Serial} · {c.Subject} · expires {c.NotAfterUtc:u}");
            }
        }
        return sb.ToString();
    }
}
