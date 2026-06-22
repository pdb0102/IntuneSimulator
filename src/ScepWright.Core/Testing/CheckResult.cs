using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>The result of one check: its verdict, the expected vs. observed failInfo, and explanation.</summary>
/// <param name="Name">The check's name.</param>
/// <param name="Outcome">The verdict.</param>
/// <param name="Expected">The failInfo the check expected (None when not applicable).</param>
/// <param name="Got">The failInfo the server returned.</param>
/// <param name="GotStatus">The server's pkiStatus (distinct from the verdict).</param>
/// <param name="Why">Human-readable explanation.</param>
/// <param name="RfcReference">The RFC section exercised.</param>
/// <param name="Elapsed">Time the check took.</param>
public sealed record CheckResult(
    string Name,
    CheckOutcome Outcome,
    FailInfo Expected,
    FailInfo Got,
    PkiStatus GotStatus,
    string Why,
    string RfcReference,
    System.TimeSpan Elapsed);
