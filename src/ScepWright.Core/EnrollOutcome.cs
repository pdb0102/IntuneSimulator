using System;
using System.Security.Cryptography.X509Certificates;
using ScepWright.Crypto;

namespace ScepWright.Core;

/// <summary>The result of a SCEP enrollment or renewal attempt.</summary>
public sealed class EnrollOutcome {
    /// <summary>Gets the client-side outcome category.</summary>
    public ScepClientResult Status { get; init; }
    /// <summary>Gets the server's pkiStatus.</summary>
    public PkiStatus PkiStatus { get; init; }
    /// <summary>Gets the failInfo when the request failed.</summary>
    public FailInfo FailInfo { get; init; } = FailInfo.None;
    /// <summary>Gets the issued certificate on success.</summary>
    public X509Certificate2? Certificate { get; init; }
    /// <summary>Gets the subject key paired with the issued certificate.</summary>
    public IScepKey? SubjectKey { get; init; }
    /// <summary>Gets the SCEP transaction id.</summary>
    public string TransactionId { get; init; } = string.Empty;
    /// <summary>Gets the wall-clock time the operation took.</summary>
    public TimeSpan Elapsed { get; init; }
    /// <summary>
    /// Gets the senderNonce we sent (RFC 8894 §3.2.1.1). A conformant server echoes it back in
    /// <see cref="RecipientNonce"/>; null means the attribute was absent.
    /// </summary>
    public byte[]? SenderNonce { get; init; }
    /// <summary>Gets the recipientNonce the server echoed; should equal <see cref="SenderNonce"/>.</summary>
    public byte[]? RecipientNonce { get; init; }
}
