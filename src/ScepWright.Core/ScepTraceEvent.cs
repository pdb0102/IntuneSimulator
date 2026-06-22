namespace ScepWright.Core;

/// <summary>Severity/category of a trace event.</summary>
public enum TraceLevel {
    /// <summary>Detailed diagnostic output.</summary>
    Debug,
    /// <summary>Normal progress information.</summary>
    Info,
    /// <summary>A non-fatal concern.</summary>
    Warning,
    /// <summary>A failure.</summary>
    Error,
    /// <summary>An interpretive opinion about server behavior.</summary>
    Opinion
}

/// <summary>A single diagnostic trace event emitted during a SCEP operation.</summary>
public sealed record ScepTraceEvent(TraceLevel Level, string Phase, string Message);
