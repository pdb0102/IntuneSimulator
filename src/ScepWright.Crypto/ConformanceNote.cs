namespace ScepWright.Crypto;

/// <summary>The severity of a conformance note.</summary>
public enum NoteSeverity {
    /// <summary>Informational observation.</summary>
    Info,
    /// <summary>A deviation worth flagging.</summary>
    Warning
}

/// <summary>A note recorded while decoding, describing a protocol observation and its RFC reference.</summary>
public sealed record ConformanceNote(NoteSeverity Severity, string What, string Where, string RfcReference);
