namespace IntuneSimulator.Core.Recording;

/// <summary>Destination for per-request log lines. Defaults to the console; tests can redirect it.</summary>
public sealed class RequestLogSink
{
    private readonly object _gate = new();
    /// <summary>Gets or sets the writer log lines are sent to. Defaults to the console.</summary>
    public TextWriter Writer { get; set; } = Console.Out;

    /// <summary>Writes a single log line to the sink in a thread-safe manner.</summary>
    public void WriteLine(string line)
    {
        lock (_gate) Writer.WriteLine(line);
    }
}
