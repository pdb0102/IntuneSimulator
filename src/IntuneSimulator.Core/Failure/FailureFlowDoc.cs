using System.Text;

namespace IntuneSimulator.Core.Failure;

/// <summary>Renders human-readable documentation of the failure-flow matrix.</summary>
public static class FailureFlowDoc
{
    /// <summary>Markdown documenting which endpoint fails (and how) at each verification attempt.</summary>
    public static string Render()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Failure-Flow Matrix");
        sb.AppendLine();
        sb.AppendLine("When failure-flow is enabled, each verification attempt fails at one cell below, in order.");
        sb.AppendLine("The cursor injects its failure on every hit to that endpoint; earlier endpoints succeed.");
        sb.AppendLine("After the last step, every endpoint succeeds (full happy path).");
        sb.AppendLine();
        sb.AppendLine($"**`Step` is 0-based and is exactly the value for `setStep` / the reported `stepIndex` (reset → step 0). Step {FailureChain.Matrix.Count} = all endpoints succeed.**");
        sb.AppendLine();
        sb.AppendLine("> **`reset` rewinds, it does not disarm.** Three states: (1) mode `off` (the default) injects");
        sb.AppendLine($"> *nothing* — the real clean slate; (2) mode `manual`/`auto` at step 0..{FailureChain.Matrix.Count - 1} injects that step's");
        sb.AppendLine("> failure (**step 0 is the FIRST failure**); (3) the last step keeps stepping on but lets every");
        sb.AppendLine($"> endpoint succeed. So `reset` returns to step 0 (the first failure), NOT to a no-fault state —");
        sb.AppendLine($"> for that set mode `off`, or `setStep {FailureChain.Matrix.Count}` to walk the all-succeed path while still stepping.");
        sb.AppendLine();
        sb.AppendLine("| Step | Endpoint | Failure mode | Soft HTTP status |");
        sb.AppendLine("|---|---|---|---|");
        foreach (var s in FailureChain.Matrix)
            sb.AppendLine($"| {s.Index} | {s.EndpointTitle} (`{s.EndpointId}`) | {s.Mode} | {s.Mode.SoftStatus()} |");
        sb.AppendLine($"| {FailureChain.Matrix.Count} | (all endpoints) | none — success | 200 |");
        return sb.ToString();
    }
}
