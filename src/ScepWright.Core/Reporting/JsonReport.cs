using System.Linq;
using System.Text.Json;
using ScepWright.Core.Testing;

namespace ScepWright.Core.Reporting;

/// <summary>Renders a test report as indented JSON.</summary>
public static class JsonReport {
    /// <summary>Serializes the report to a JSON document.</summary>
    public static string Emit(TestReport report) {
        object payload;

        payload = new {
            serverId = report.ServerId,
            mode = report.Mode,
            generatedUtc = report.GeneratedUtc.ToString("u"),
            toolVersion = report.ToolVersion,
            target = report.TargetUrl,
            caThumbprint = report.CaThumbprint,
            totals = new { passed = report.Passed, failed = report.Failed, skipped = report.Skipped, findings = report.Findings },
            totalElapsedMs = (long)report.TotalElapsed.TotalMilliseconds,
            results = report.Results.Select(r => new {
                name = r.Name,
                outcome = r.Outcome.ToString(),
                expected = r.Expected.ToString(),
                got = r.Got.ToString(),
                // The server's SCEP pkiStatus for this check (NOT the verdict — that's `outcome`). A PASSED
                // negative check legitimately shows pkiStatus "Failure" because rejection is the pass condition.
                pkiStatus = r.GotStatus.ToString(),
                why = r.Why,
                rfc = r.RfcReference,
                elapsedMs = (long)r.Elapsed.TotalMilliseconds,
            }).ToArray(),
            footprint = report.Footprint.Select(c => new {
                serial = c.Serial,
                subject = c.Subject,
                notAfterUtc = c.NotAfterUtc.ToString("u"),
            }).ToArray(),
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }
}
