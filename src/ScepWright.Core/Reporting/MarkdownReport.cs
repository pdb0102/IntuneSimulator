using System.Text;
using ScepWright.Core.Testing;

namespace ScepWright.Core.Reporting;

/// <summary>Renders a test report as a Markdown document with results and footprint tables.</summary>
public static class MarkdownReport {
    /// <summary>Formats the report as Markdown.</summary>
    public static string Emit(TestReport report) {
        StringBuilder sb;

        sb = new StringBuilder();
        sb.AppendLine($"# SCEP test run — {report.ServerId} — {report.Mode}");
        sb.AppendLine();
        sb.AppendLine($"- Generated: {report.GeneratedUtc:u}");
        sb.AppendLine($"- Target: {report.TargetUrl}");
        sb.AppendLine($"- Tool version: {report.ToolVersion}");
        sb.AppendLine($"- CA thumbprint: {report.CaThumbprint}");
        sb.AppendLine();
        sb.AppendLine($"PASSED {report.Passed} · FAILED {report.Failed} · SKIPPED {report.Skipped} · FINDINGS {report.Findings} · {report.TotalElapsed.TotalSeconds:0.0}s");
        sb.AppendLine();
        sb.AppendLine("| Check | Outcome | Expected | Got | Why | RFC |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (CheckResult r in report.Results) {
            sb.AppendLine($"| {Cell(r.Name)} | {r.Outcome} | {r.Expected} | {r.Got} | {Cell(r.Why)} | {Cell(r.RfcReference)} |");
        }
        if (report.Footprint.Count > 0) {
            sb.AppendLine();
            sb.AppendLine($"## Footprint — {report.Footprint.Count} real certificate(s) issued (revoke / clean up)");
            sb.AppendLine();
            sb.AppendLine("| Serial | Subject | Expires (UTC) |");
            sb.AppendLine("|---|---|---|");
            foreach (IssuedCert c in report.Footprint) {
                sb.AppendLine($"| {Cell(c.Serial)} | {Cell(c.Subject)} | {c.NotAfterUtc:u} |");
            }
        }
        return sb.ToString();
    }

    // Keep a stray '|' in a message from breaking the Markdown table.
    private static string Cell(string text) => (text ?? string.Empty).Replace("|", "\\|");
}
