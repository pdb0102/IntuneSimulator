using System.Security.Cryptography.X509Certificates;

namespace IntuneSimulator.Core;

/// <summary>
/// Singleton holding all runtime-mutable behavior. All members are guarded by <see cref="_gate"/>.
/// Later tasks extend this (canned SCEP codes, revocation queue, failure-flow cursor).
/// </summary>
public sealed class SimulatorState
{
    private readonly object _gate = new();
    private string _authPassword;
    private string _challengePassword;
    private X509Certificate2? _authCertificate;

    private bool _logRequests;

    /// <summary>Initializes the mutable state from the immutable <paramref name="options"/>.</summary>
    public SimulatorState(SimulatorOptions options)
    {
        Options = options;
        _authPassword = options.AuthPassword;
        _challengePassword = options.ChallengePasswordOverride
            ?? Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("intune-scep:" + options.AuthPassword));
        if (options.AuthCertificatePfxBase64 is not null)
        {
            _authCertificate = new X509Certificate2(
                Convert.FromBase64String(options.AuthCertificatePfxBase64),
                options.AuthCertificatePassword);
        }
        _logRequests = options.LogRequests;
    }

    /// <summary>Gets the immutable startup options this state was created from.</summary>
    public SimulatorOptions Options { get; }

    /// <summary>Gets or sets the password accepted as the client-credentials secret.</summary>
    public string AuthPassword
    {
        get { lock (_gate) return _authPassword; }
        set { lock (_gate) _authPassword = value; }
    }

    /// <summary>Gets or sets the SCEP challenge password.</summary>
    public string ChallengePassword
    {
        get { lock (_gate) return _challengePassword; }
        set { lock (_gate) _challengePassword = value; }
    }

    /// <summary>Gets or sets the certificate used to validate client-assertion auth. Null = cert auth disabled.</summary>
    public X509Certificate2? AuthCertificate
    {
        get { lock (_gate) return _authCertificate; }
        set { lock (_gate) _authCertificate = value; }
    }

    /// <summary>Gets or sets a value indicating whether each request is logged.</summary>
    public bool LogRequests
    {
        get { lock (_gate) return _logRequests; }
        set { lock (_gate) _logRequests = value; }
    }

    private string? _cannedScepCode;
    /// <summary>Gets or sets a canned SCEP error-code name to return instead of normal processing. Null = disabled.</summary>
    public string? CannedScepCode
    {
        get { lock (_gate) return _cannedScepCode; }
        set { lock (_gate) _cannedScepCode = value; }
    }

    private readonly List<Revocation.RevocationRequestItem> _revocationQueue = new();

    /// <summary>Gets a snapshot of the pending revocation requests.</summary>
    public IReadOnlyList<Revocation.RevocationRequestItem> RevocationQueue
    {
        get { lock (_gate) return _revocationQueue.ToArray(); }
    }

    /// <summary>Gets the number of pending revocation requests.</summary>
    public int RevocationQueueCount { get { lock (_gate) return _revocationQueue.Count; } }

    /// <summary>Adds a revocation request to the pending queue.</summary>
    public void EnqueueRevocation(Revocation.RevocationRequestItem item) { lock (_gate) _revocationQueue.Add(item); }

    /// <summary>Removes and returns up to <paramref name="max"/> pending revocation requests, optionally filtered by issuer.</summary>
    /// <param name="max">Maximum number of requests to return.</param>
    /// <param name="issuerName">When non-null, only requests whose issuer matches (case-insensitive) are returned.</param>
    public List<Revocation.RevocationRequestItem> DequeueRevocations(int max, string? issuerName = null)
    {
        lock (_gate)
        {
            var result = new List<Revocation.RevocationRequestItem>();
            int idx = 0;
            int limit = Math.Max(max, 0);
            while (idx < _revocationQueue.Count && result.Count < limit)
            {
                var item = _revocationQueue[idx];
                if (issuerName is null || string.Equals(item.IssuerName, issuerName, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(item);
                    _revocationQueue.RemoveAt(idx);
                }
                else
                {
                    idx++;
                }
            }
            return result;
        }
    }
}
