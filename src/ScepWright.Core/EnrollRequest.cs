using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepWright.Crypto;

namespace ScepWright.Core;

/// <summary>Inputs for an initial SCEP certificate enrollment (PKCSReq).</summary>
public sealed class EnrollRequest {
    /// <summary>Gets the subject DN to request.</summary>
    public required string Subject { get; init; }
    /// <summary>Gets the subject key pair.</summary>
    public required IScepKey Key { get; init; }
    /// <summary>Gets an optional second subject key for hybrid/dual-key enrollment.</summary>
    public IScepKey? AltKey { get; init; }
    /// <summary>Gets the textual key spec used to generate the key, for reporting.</summary>
    public string? KeySpecText { get; init; }
    /// <summary>Gets the SCEP challenge password, if required by the server.</summary>
    public string? ChallengePassword { get; init; }
    /// <summary>Gets the signature digest algorithm OID. Defaults to SHA-256.</summary>
    public string DigestOid { get; init; } = Algorithms.OidFor("SHA-256")!;
    /// <summary>Gets the envelope content-encryption algorithm OID. Defaults to AES-128-CBC.</summary>
    public string ContentEncryptionOid { get; init; } = Algorithms.OidFor("AES-128-CBC")!;
    /// <summary>Gets the DNS subject alternative names to request.</summary>
    public List<string> DnsNames { get; } = new();
    /// <summary>Gets the UPN subject alternative names to request.</summary>
    public List<string> Upns { get; } = new();
    /// <summary>Gets the security identifier (SID) to embed, if any.</summary>
    public string? Sid { get; init; }
    /// <summary>Gets the requested extended key usage OIDs.</summary>
    public List<string> Ekus { get; } = new();
    /// <summary>Gets or sets the CA certificate to envelope to; resolved from the server if null.</summary>
    public X509Certificate2? CaCertificate { get; set; }
}
