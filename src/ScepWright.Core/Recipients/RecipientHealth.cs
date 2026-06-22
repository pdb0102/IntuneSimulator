using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ScepWright.Core.Recipients;

/// <summary>
/// Temporal-validity warnings for a chosen SCEP envelope recipient. An expired or not-yet-valid
/// recipient can still be enveloped to crypto-wise, so <see cref="RecipientSelector"/> still selects
/// it — but real clients/servers reject such a cert, so callers must downgrade the verdict rather than
/// report OK.
/// </summary>
public static class RecipientHealth {
    /// <summary>Returns warnings if the recipient certificate is expired or not yet valid; empty otherwise.</summary>
    public static IReadOnlyList<string> TemporalWarnings(X509Certificate2 cert) {
        List<string> warnings;
        DateTime now;
        DateTime not_before;
        DateTime not_after;

        warnings = new List<string>();
        now = DateTime.UtcNow;
        not_before = cert.NotBefore.ToUniversalTime();
        not_after = cert.NotAfter.ToUniversalTime();

        if (not_after < now) {
            warnings.Add($"recipient certificate is EXPIRED (expired {not_after:u}); clients will reject the envelope");
        } else if (not_before > now) {
            warnings.Add($"recipient certificate is NOT YET VALID (valid from {not_before:u}); clients will reject the envelope");
        }
        return warnings;
    }
}
