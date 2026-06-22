using System;
using ScepWright.Core;

namespace ScepWright.Client;

internal sealed class ConsoleTrace {
    private readonly int _verbosity;

    public ConsoleTrace(int verbosity) { _verbosity = verbosity; }

    public void Handle(ScepTraceEvent trace_event) {
        if (trace_event.Level == TraceLevel.Debug && _verbosity < 1) { return; }
        Console.Error.WriteLine($"[{trace_event.Level}] {trace_event.Phase}: {trace_event.Message}");
    }
}
