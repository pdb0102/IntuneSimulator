namespace IntuneSimulator.Core.Failure;

public enum FailureMode
{
    Timeout,
    ConnectionRefused,
    Http500,
    Http503,
    Http401,
    InvalidClient400,
    MalformedJson,
    ScepError,
}

public static class FailureModeExtensions
{
    /// <summary>HTTP status used when "soft" faulting (TestServer / HardFaults=off). See FailureFlowMiddleware.</summary>
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
