using ScepWright.Crypto;

namespace ScepWright.Core;

/// <summary>
/// Outcome of sending a byte-identical PKIMessage twice (the conformance engine's anti-replay probe).
/// <paramref name="Sent"/> is false only when the request could not be transmitted at all
/// (encode/transport failure), making the probe inconclusive; otherwise <paramref name="First"/> and
/// <paramref name="Second"/> carry each send's pkiStatus, with their failInfo.
/// </summary>
public sealed record ReplayProbe(bool Sent, string Error, PkiStatus First, FailInfo FirstFail, PkiStatus Second, FailInfo SecondFail);
