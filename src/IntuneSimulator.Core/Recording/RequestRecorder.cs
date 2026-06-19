using System.Collections.Concurrent;

namespace IntuneSimulator.Core.Recording;

public sealed record RecordedRequest(string Endpoint, string Body, DateTimeOffset At);

/// <summary>In-memory log of received SCEP/revocation requests, for test assertions and the info page.</summary>
public sealed class RequestRecorder
{
    private readonly ConcurrentQueue<RecordedRequest> _items = new();
    public void Record(string endpoint, string body) => _items.Enqueue(new RecordedRequest(endpoint, body, DateTimeOffset.UtcNow));
    public IReadOnlyList<RecordedRequest> Snapshot() => _items.ToArray();
    public void Clear() => _items.Clear();
}
