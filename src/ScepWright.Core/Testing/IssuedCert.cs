namespace ScepWright.Core.Testing;

/// <summary>
/// One certificate a live suite caused the target CA to issue. The footprint of these is printed
/// after a run so the operator can revoke or clean up the real certs the test minted.
/// </summary>
public sealed record IssuedCert(string Serial, string Subject, System.DateTime NotAfterUtc) {
    /// <summary>Creates a footprint entry from an issued certificate.</summary>
    public static IssuedCert From(System.Security.Cryptography.X509Certificates.X509Certificate2 cert) =>
        new(cert.SerialNumber, cert.Subject, cert.NotAfter.ToUniversalTime());
}
