using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>Parses and runs a JSON-described scenario playlist of SCEP steps against a server.</summary>
public static class ScenarioRunner {
    /// <summary>
    /// Parses a scenario from JSON, validating every step's Run verb, Expect token, and Args keys so a
    /// typo fails loudly rather than silently scoring green.
    /// </summary>
    public static bool Parse(string json, out ScenarioFile scenario, out string error) {
        ScenarioFile? parsed;

        scenario = null!;
        error = string.Empty;
        try {
            parsed = JsonSerializer.Deserialize<ScenarioFile>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        } catch (System.Exception ex) {
            error = ex.Message;
            return false;
        }
        if (parsed == null) { error = "empty scenario"; return false; }

        foreach (ScenarioStep step in parsed.Steps) {
            if (!IsKnownVerb(step.Run)) {
                error = $"step '{step.Name}': unknown Run verb '{step.Run}' (supported: getcacaps, enroll, probe)";
                return false;
            }
            if (!IsKnownExpect(step.Expect)) {
                error = $"step '{step.Name}': unknown Expect '{step.Expect}' (supported: pass, fail, badAlg, badMessageCheck, badTime, badRequest, badCertId)";
                return false;
            }
            if (step.Args != null) {
                foreach (string key in step.Args.Keys) {
                    if (!IsKnownArgKey(key)) {
                        error = $"step '{step.Name}': unknown Args key '{key}' (supported: subject, digest, cipher, challenge)";
                        return false;
                    }
                }
            }
        }

        scenario = parsed;
        return true;
    }

    private static bool IsKnownVerb(string run) {
        switch ((run ?? string.Empty).ToLowerInvariant()) {
            case "getcacaps":
            case "enroll":
            case "probe":
                return true;
            default:
                return false;
        }
    }

    // An empty/absent Expect defaults to "pass"; otherwise it must be a token Matches understands, so a
    // typo can't silently degrade into "expect failInfo None" and score green for the wrong reason.
    private static bool IsKnownExpect(string? expect) {
        switch ((expect ?? "pass").ToLowerInvariant()) {
            case "pass":
            case "fail":
            case "badalg":
            case "badmessagecheck":
            case "badtime":
            case "badrequest":
            case "badcertid":
                return true;
            default:
                return false;
        }
    }

    // Only these Args keys are consumed by ExecuteStep; reject anything else so a playlist that tries to
    // drive an unsupported option (e.g. "ndes") fails loudly instead of silently doing nothing.
    private static bool IsKnownArgKey(string key) {
        switch ((key ?? string.Empty).ToLowerInvariant()) {
            case "subject":
            case "digest":
            case "cipher":
            case "challenge":
                return true;
            default:
                return false;
        }
    }

    /// <summary>Executes each step of the scenario and returns the aggregated report.</summary>
    public static TestReport Run(ScepClient client, ScenarioFile scenario, X509Certificate2 ca_cert) {
        TestReport report;
        Stopwatch total;

        report = new TestReport { ServerId = client.Server.Id, Mode = "scenario" };
        total = Stopwatch.StartNew();
        foreach (ScenarioStep step in scenario.Steps) {
            report.Results.Add(RunStep(client, ca_cert, step));
        }
        total.Stop();
        report.TotalElapsed = total.Elapsed;
        return report;
    }

    private static CheckResult RunStep(ScepClient client, X509Certificate2 ca_cert, ScenarioStep step) {
        Stopwatch sw;
        PkiStatus status;
        FailInfo got;
        bool matched;
        string why;

        sw = Stopwatch.StartNew();
        ExecuteStep(client, ca_cert, step, out status, out got);
        sw.Stop();

        matched = Matches(step.Expect, status, got);
        why = matched ? $"matched expect '{step.Expect}'" : $"expected '{step.Expect}', got status {status} failInfo {got}";
        return new CheckResult(step.Name, matched ? CheckOutcome.Passed : CheckOutcome.Failed,
            ExpectToFailInfo(step.Expect), got, status, why, "scenario", sw.Elapsed);
    }

    private static void ExecuteStep(ScepClient client, X509Certificate2 ca_cert, ScenarioStep step, out PkiStatus status, out FailInfo got) {
        ScepRequestBuilder builder;
        PkiMessage message;
        IScepKey key;
        string error;
        ScepResult<EnrollOutcome> result;

        status = PkiStatus.Failure;
        got = FailInfo.None;
        switch (step.Run.ToLowerInvariant()) {
            case "getcacaps":
                status = client.GetCaCaps().IsOk ? PkiStatus.Success : PkiStatus.Failure;
                return;
            case "enroll":
            case "probe":
                builder = ScepRequestBuilder.For(client.Crypto)
                    .CaCertificate(ca_cert)
                    .MessageType(MessageType.PkcsReq)
                    .Subject(step.Args.TryGetValue("subject", out string? subj) ? subj : "CN=scenario")
                    // Deliberate baseline probe: rsa:2048 keeps scenario probes key-agnostic.
                    .KeySpec("rsa:2048");
                if (step.Args.TryGetValue("digest", out string? digest)) { builder.Digest(digest); }
                if (step.Args.TryGetValue("cipher", out string? cipher)) { builder.Cipher(cipher); }
                if (step.Args.TryGetValue("challenge", out string? ch)) { builder.Challenge(ch); }
                if (!builder.Build(out message, out key, out error)) { return; }
                result = client.SubmitPkiOperation(message, key, builder.Faults);
                status = result.Value?.PkiStatus ?? PkiStatus.Failure;
                got = result.Value?.FailInfo ?? FailInfo.None;
                return;
            default:
                return;
        }
    }

    private static bool Matches(string? expect, PkiStatus status, FailInfo got) {
        switch ((expect ?? "pass").ToLowerInvariant()) {
            case "pass": return status == PkiStatus.Success;
            case "fail": return status != PkiStatus.Success;
            default: return status != PkiStatus.Success && got == ExpectToFailInfo(expect);
        }
    }

    private static FailInfo ExpectToFailInfo(string? expect) {
        switch ((expect ?? string.Empty).ToLowerInvariant()) {
            case "badalg": return FailInfo.BadAlg;
            case "badmessagecheck": return FailInfo.BadMessageCheck;
            case "badtime": return FailInfo.BadTime;
            case "badrequest": return FailInfo.BadRequest;
            case "badcertid": return FailInfo.BadCertId;
            default: return FailInfo.None;
        }
    }
}
