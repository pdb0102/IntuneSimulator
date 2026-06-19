using System.Text;

namespace IntuneSimulator.Core.Failure;

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
        sb.AppendLine("| Attempt | Endpoint | Failure mode | Soft HTTP status |");
        sb.AppendLine("|---|---|---|---|");
        foreach (var s in FailureChain.Matrix)
            sb.AppendLine($"| {s.Index + 1} | {s.EndpointTitle} (`{s.EndpointId}`) | {s.Mode} | {s.Mode.SoftStatus()} |");
        sb.AppendLine($"| {FailureChain.Matrix.Count + 1} | (all endpoints) | none — success | 200 |");
        return sb.ToString();
    }
}
