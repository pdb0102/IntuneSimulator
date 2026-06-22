using System.Security.Cryptography.X509Certificates;
using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>The result of the Jamf-style poll-to-completion enrollment simulation.</summary>
/// <param name="TimedOut">Whether polling gave up before completion.</param>
/// <param name="FinalStatus">The final pkiStatus observed.</param>
/// <param name="Elapsed">Total time spent.</param>
/// <param name="PollCount">Number of poll attempts made.</param>
/// <param name="Certificate">The issued certificate, if enrollment completed.</param>
public sealed record JamfResult(
    bool TimedOut,
    PkiStatus FinalStatus,
    System.TimeSpan Elapsed,
    int PollCount,
    X509Certificate2? Certificate);
