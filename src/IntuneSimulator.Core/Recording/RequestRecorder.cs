using System.Collections.Concurrent;

namespace IntuneSimulator.Core.Recording;

/// <summary>A single recorded request.</summary>
/// <param name="Endpoint">The endpoint path that received the request.</param>
/// <param name="Body">The captured request body.</param>
/// <param name="At">When the request was recorded.</param>
public sealed record RecordedRequest(string Endpoint, string Body, DateTimeOffset At);

/// <summary>In-memory log of received SCEP/revocation requests, for test assertions and the info page.</summary>
public sealed class RequestRecorder
{
    private readonly ConcurrentQueue<RecordedRequest> _items = new();
    /// <summary>Records the body received at the given endpoint with the current timestamp.</summary>
    public void Record(string endpoint, string body) => _items.Enqueue(new RecordedRequest(endpoint, body, DateTimeOffset.UtcNow));
    /// <summary>Returns a snapshot of all recorded requests.</summary>
    public IReadOnlyList<RecordedRequest> Snapshot() => _items.ToArray();
    /// <summary>Clears all recorded requests.</summary>
    public void Clear() => _items.Clear();
}
