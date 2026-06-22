using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ScepWright.Crypto;

namespace ScepWright.Core;

/// <summary>Inputs for a SCEP certificate renewal or re-enrollment.</summary>
public sealed class RenewRequest {
    /// <summary>Gets the subject DN to request.</summary>
    public required string Subject { get; init; }
    /// <summary>Gets the existing certificate used to authenticate the renewal.</summary>
    public required X509Certificate2 ExistingCertificate { get; init; }
    /// <summary>Gets the private key for <see cref="ExistingCertificate"/>.</summary>
    public required IScepKey ExistingKey { get; init; }
    /// <summary>Gets the renewal shape (message type and signing/key strategy). Defaults to <see cref="RenewalVariant.Proper"/>.</summary>
    public RenewalVariant Variant { get; init; } = RenewalVariant.Proper;
    /// <summary>Gets the SCEP challenge password, if required.</summary>
    public string? ChallengePassword { get; init; }
    /// <summary>Gets the textual key spec for the new key, for reporting.</summary>
    public string KeySpecText { get; init; } = string.Empty;
    /// <summary>Gets the signature digest algorithm OID. Defaults to SHA-256.</summary>
    public string DigestOid { get; init; } = Algorithms.OidFor("SHA-256")!;
    /// <summary>Gets the envelope content-encryption algorithm OID. Defaults to AES-128-CBC.</summary>
    public string ContentEncryptionOid { get; init; } = Algorithms.OidFor("AES-128-CBC")!;
    /// <summary>Gets the DNS subject alternative names to request.</summary>
    public List<string> DnsNames { get; } = new();
    /// <summary>Gets the UPN subject alternative names to request.</summary>
    public List<string> Upns { get; } = new();
    /// <summary>Gets the requested extended key usage OIDs.</summary>
    public List<string> Ekus { get; } = new();
    /// <summary>Gets the security identifier (SID) to embed, if any.</summary>
    public string? Sid { get; init; }
    /// <summary>Gets or sets the CA certificate to envelope to; resolved from the server if null.</summary>
    public X509Certificate2? CaCertificate { get; set; }
}
