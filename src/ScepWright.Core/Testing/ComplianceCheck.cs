using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>The definition of a single compliance check: the fault to inject and the expected rejection.</summary>
/// <param name="Name">The check's name.</param>
/// <param name="Kind">The fault to inject.</param>
/// <param name="Expected">The failInfo a conformant server should return.</param>
/// <param name="RfcReference">The RFC section this exercises.</param>
/// <param name="FindingWhy">
/// Optional message overriding the generic "more lenient than spec" text when a server accepts a
/// request the RFC permits it to reject; used by the security/leniency checks to say what was lax.
/// </param>
public sealed record ComplianceCheck(string Name, FaultKind Kind, FailInfo Expected, string RfcReference, string? FindingWhy = null);
