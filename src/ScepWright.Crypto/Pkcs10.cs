using System.Collections.Generic;

namespace ScepWright.Crypto;

/// <summary>A description of a PKCS#10 certificate-signing request to be built by a crypto provider.</summary>
public sealed class Pkcs10 {
    /// <summary>Gets the subject DN. Set via <see cref="SetSubject"/>.</summary>
    public string Subject { get; private set; } = string.Empty;
    /// <summary>Gets or sets the subject key pair.</summary>
    public IScepKey? Key { get; set; }
    /// <summary>Gets or sets an alternate (second) subject key for hybrid/dual-key requests.</summary>
    public IScepKey? AltKey { get; set; }
    /// <summary>Gets or sets the SCEP challenge password attribute.</summary>
    public string? ChallengePassword { get; set; }
    /// <summary>Gets the DNS subject alternative names.</summary>
    public List<string> DnsNames { get; } = new();
    /// <summary>Gets the UPN (otherName) subject alternative names.</summary>
    public List<string> Upns { get; } = new();
    /// <summary>Gets or sets the security identifier (SID) to embed.</summary>
    public string? Sid { get; set; }
    /// <summary>Gets the requested extended key usage OIDs.</summary>
    public List<string> Ekus { get; } = new();
    /// <summary>Gets additional raw extensions to include, as (OID, DER value, critical) tuples.</summary>
    public List<(string Oid, byte[] Value, bool Critical)> Extensions { get; } = new();

    /// <summary>Sets the subject DN, rejecting an empty value.</summary>
    public bool SetSubject(string subject, out string error) {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(subject)) {
            error = "subject DN must be non-empty";
            return false;
        }
        Subject = subject;
        return true;
    }
}
