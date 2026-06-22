namespace ScepWright.Core.Testing;

/// <summary>The verdict of a single conformance/compliance check.</summary>
public enum CheckOutcome {
    /// <summary>The server behaved as the RFC requires.</summary>
    Passed,
    /// <summary>The server violated the RFC.</summary>
    Failed,
    /// <summary>The check was inconclusive (e.g. PENDING or unsupported capability).</summary>
    Skipped,
    /// <summary>The server was more lenient than the spec allows (a notable laxity).</summary>
    Finding
}
