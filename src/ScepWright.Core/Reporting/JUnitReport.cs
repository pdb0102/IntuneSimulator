using System.Xml.Linq;
using ScepWright.Core.Testing;

namespace ScepWright.Core.Reporting;

/// <summary>Renders a test report as a JUnit XML test suite.</summary>
public static class JUnitReport {
    /// <summary>Emits JUnit XML, treating leniency findings as informational.</summary>
    public static string Emit(TestReport report) {
        return Emit(report, false);
    }

    /// <summary>
    /// Emits JUnit XML. When <paramref name="fail_on_findings"/> is set, leniency findings are emitted
    /// as failures (and counted) so a CI job gating on the report — not just the exit code — catches them.
    /// </summary>
    public static string Emit(TestReport report, bool fail_on_findings) {
        XElement suite;
        int failure_count;

        failure_count = report.Failed + (fail_on_findings ? report.Findings : 0);
        suite = new XElement("testsuite",
            new XAttribute("name", $"scep-{report.ServerId}-{report.Mode}"),
            new XAttribute("tests", report.Results.Count),
            new XAttribute("failures", failure_count),
            new XAttribute("skipped", report.Skipped),
            new XAttribute("time", report.TotalElapsed.TotalSeconds),
            new XAttribute("timestamp", report.GeneratedUtc.ToString("u")),
            new XElement("properties",
                new XElement("property", new XAttribute("name", "target"), new XAttribute("value", report.TargetUrl)),
                new XElement("property", new XAttribute("name", "toolVersion"), new XAttribute("value", report.ToolVersion)),
                new XElement("property", new XAttribute("name", "caThumbprint"), new XAttribute("value", report.CaThumbprint))));

        foreach (CheckResult result in report.Results) {
            XElement test_case;

            test_case = new XElement("testcase",
                new XAttribute("name", result.Name),
                new XAttribute("classname", $"scep.{report.Mode}"),
                new XAttribute("time", result.Elapsed.TotalSeconds));

            if (result.Outcome == CheckOutcome.Failed) {
                string message;
                message = (result.Expected != ScepWright.Crypto.FailInfo.None || result.Got != ScepWright.Crypto.FailInfo.None)
                    ? $"{result.Why} (expected failInfo {result.Expected}, got {result.Got})"
                    : result.Why;
                test_case.Add(new XElement("failure",
                    new XAttribute("message", message),
                    result.Why + " (" + result.RfcReference + ")"));
            } else if (result.Outcome == CheckOutcome.Finding && fail_on_findings) {
                test_case.Add(new XElement("failure",
                    new XAttribute("message", "leniency finding: " + result.Why),
                    "FINDING: " + result.Why + " (" + result.RfcReference + ")"));
            } else if (result.Outcome == CheckOutcome.Finding) {
                test_case.Add(new XElement("system-out", "FINDING: " + result.Why + " (" + result.RfcReference + ")"));
            } else if (result.Outcome == CheckOutcome.Skipped) {
                test_case.Add(new XElement("skipped", new XAttribute("message", result.Why)));
            }
            suite.Add(test_case);
        }

        return new XDocument(new XElement("testsuites", suite)).ToString();
    }
}
