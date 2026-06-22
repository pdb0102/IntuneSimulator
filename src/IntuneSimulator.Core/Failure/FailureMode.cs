namespace IntuneSimulator.Core.Failure;

/// <summary>The kinds of failure the simulator can inject into a request.</summary>
public enum FailureMode
{
    /// <summary>A request timeout (hard: socket delay then abort; soft: HTTP 504).</summary>
    Timeout,
    /// <summary>A refused connection (hard: abort; soft: HTTP 502).</summary>
    ConnectionRefused,
    /// <summary>An HTTP 500 Internal Server Error.</summary>
    Http500,
    /// <summary>An HTTP 503 Service Unavailable.</summary>
    Http503,
    /// <summary>An HTTP 401 Unauthorized.</summary>
    Http401,
    /// <summary>An HTTP 400 with an invalid_client OAuth error body.</summary>
    InvalidClient400,
    /// <summary>An HTTP 200 with a truncated, unparseable JSON body.</summary>
    MalformedJson,
    /// <summary>An HTTP 200 carrying a simulated SCEP error code.</summary>
    ScepError,
}

/// <summary>Extension helpers for <see cref="FailureMode"/>.</summary>
public static class FailureModeExtensions
{
    /// <summary>Returns the HTTP status used when "soft" faulting (TestServer / HardFaults=off). See FailureFlowMiddleware.</summary>
    public static int SoftStatus(this FailureMode m) => m switch
    {
        FailureMode.Timeout => 504,
        FailureMode.ConnectionRefused => 502,
        FailureMode.Http500 => 500,
        FailureMode.Http503 => 503,
        FailureMode.Http401 => 401,
        FailureMode.InvalidClient400 => 400,
        FailureMode.MalformedJson => 200,
        FailureMode.ScepError => 200,
        _ => 500,
    };
}
