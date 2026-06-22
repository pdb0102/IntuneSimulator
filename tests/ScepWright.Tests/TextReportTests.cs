using System.Text.Json;
using ScepWright.Core.Reporting;
using ScepWright.Core.Testing;
using ScepWright.Crypto;

namespace ScepWright.Tests;

public sealed class TextReportTests {
    private static TestReport Sample() {
        TestReport report;

        report = new TestReport { ServerId = "testhost", Mode = "full" };
        report.Results.Add(new CheckResult("ok", CheckOutcome.Passed, FailInfo.BadAlg, FailInfo.BadAlg, PkiStatus.Failure, "got expected BadAlg", "RFC 8894 §2.9", System.TimeSpan.FromMilliseconds(5)));
        report.Results.Add(new CheckResult("skew", CheckOutcome.Failed, FailInfo.BadTime, FailInfo.None, PkiStatus.Success, "server accepted +2h skew", "RFC 8894 §3.2.1", System.TimeSpan.FromMilliseconds(7)));
        report.Results.Add(new CheckResult("lenient", CheckOutcome.Finding, FailInfo.None, FailInfo.None, PkiStatus.Success, "SHA-256 works though only SHA-1 advertised", "under-advertised", System.TimeSpan.FromMilliseconds(3)));
        return report;
    }

    private static TestReport SampleWithFootprint() {
        TestReport report;

        report = Sample();
        report.Footprint.Add(new IssuedCert("0A1B2C", "CN=enrolled-1", new System.DateTime(2027, 1, 1, 0, 0, 0, System.DateTimeKind.Utc)));
        return report;
    }

    // A live run must list the real certs it minted so the operator can revoke/clean them up.
    [Fact]
    public void Console_ShowsIssuedFootprint() {
        string text;

        text = ConsoleSummary.Emit(SampleWithFootprint());
        Assert.Contains("FOOTPRINT", text);
        Assert.Contains("0A1B2C", text);
        Assert.Contains("CN=enrolled-1", text);
    }

    [Fact]
    public void Json_IncludesFootprint() {
        string json;
        JsonDocument doc;
        JsonElement footprint;

        json = JsonReport.Emit(SampleWithFootprint());
        doc = JsonDocument.Parse(json);
        footprint = doc.RootElement.GetProperty("footprint");
        Assert.Equal(1, footprint.GetArrayLength());
        Assert.Equal("0A1B2C", footprint[0].GetProperty("serial").GetString());
        Assert.Equal("CN=enrolled-1", footprint[0].GetProperty("subject").GetString());
    }

    [Fact]
    public void Markdown_IncludesFootprint() {
        string md;

        md = MarkdownReport.Emit(SampleWithFootprint());
        Assert.Contains("0A1B2C", md);
        Assert.Contains("CN=enrolled-1", md);
    }

    // The per-check `status` field is the server's PkiStatus, so a PASSED negative check
    // showed status:"Failure" — read as inverted. Rename it `pkiStatus` (and keep `outcome` as the verdict).
    [Fact]
    public void Json_names_the_server_status_field_pkiStatus_not_status() {
        string json;
        JsonDocument doc;
        JsonElement first;

        json = JsonReport.Emit(Sample());
        doc = JsonDocument.Parse(json);
        first = doc.RootElement.GetProperty("results")[0];

        Assert.True(first.TryGetProperty("pkiStatus", out _));
        Assert.False(first.TryGetProperty("status", out _));
        // The verdict is the unambiguous `outcome` field.
        Assert.Equal("Passed", first.GetProperty("outcome").GetString());
        Assert.Equal("Failure", first.GetProperty("pkiStatus").GetString());
    }

    [Fact]
    public void Json_HasTotalsAndResults() {
        string json;
        JsonDocument doc;

        json = JsonReport.Emit(Sample());
        doc = JsonDocument.Parse(json);
        Assert.Equal(1, doc.RootElement.GetProperty("totals").GetProperty("failed").GetInt32());
        Assert.Equal("testhost", doc.RootElement.GetProperty("serverId").GetString());
    }

    [Fact]
    public void Console_ShowsFailedAndFindings() {
        string text;

        text = ConsoleSummary.Emit(Sample());
        Assert.Contains("FAILED   1", text);
        Assert.Contains("FINDINGS 1", text);
        Assert.Contains("expected failInfo BadTime, got None", text);
    }

    [Fact]
    public void Junit_surfaces_findings_only_under_fail_on_findings() {
        string without;
        string with;

        without = JUnitReport.Emit(Sample(), false);
        with = JUnitReport.Emit(Sample(), true);

        // Default: 1 real failure, the finding is system-out (not a <failure>).
        Assert.Contains("failures=\"1\"", without);
        Assert.DoesNotContain("leniency finding", without);

        // --fail-on-findings: the finding becomes a <failure> and is counted.
        Assert.Contains("failures=\"2\"", with);
        Assert.Contains("leniency finding", with);
    }

    [Fact]
    public void Markdown_HasTable() {
        string md;

        md = MarkdownReport.Emit(Sample());
        Assert.Contains("| Check | Outcome", md);
        // The MD report must carry the RFC column (it was dropped though JSON/JUnit kept it).
        Assert.Contains("| RFC |", md);
        Assert.Contains("RFC 8894 §2.9", md);
    }
}
