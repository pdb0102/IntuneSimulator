namespace ScepWright.Crypto;

/// <summary>SCEP messageType attribute values (RFC 8894 §3.2.1.2).</summary>
public enum MessageType {
    /// <summary>Response from the CA (CertRep).</summary>
    CertRep = 3,
    /// <summary>Certificate renewal request (RenewalReq).</summary>
    RenewalReq = 17,
    /// <summary>Initial certificate enrollment request (PKCSReq).</summary>
    PkcsReq = 19,
    /// <summary>Poll for a pending request (CertPoll / GetCertInitial).</summary>
    CertPoll = 20,
    /// <summary>Retrieve a previously issued certificate (GetCert).</summary>
    GetCert = 21,
    /// <summary>Retrieve a CRL (GetCRL).</summary>
    GetCrl = 22,
}
