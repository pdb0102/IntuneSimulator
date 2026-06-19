namespace IntuneSimulator.Core.Recording;

/// <summary>Destination for per-request log lines. Defaults to the console; tests can redirect it.</summary>
public sealed class RequestLogSink
{
    private readonly object _gate = new();
    public TextWriter Writer { get; set; } = Console.Out;

    public void WriteLine(string line)
    {
        lock (_gate) Writer.WriteLine(line);
    }
}
