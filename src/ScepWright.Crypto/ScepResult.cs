namespace ScepWright.Crypto;

/// <summary>The result of an async SCEP operation: a status, an optional value, and an error message.</summary>
public readonly struct ScepResult<T> {
    /// <summary>Gets the outcome status.</summary>
    public ScepClientResult Status { get; }
    /// <summary>Gets the result value (default when the operation failed without one).</summary>
    public T Value { get; }
    /// <summary>Gets the error message, or empty on success.</summary>
    public string Error { get; }

    private ScepResult(ScepClientResult status, T value, string error) {
        Status = status;
        Value = value;
        Error = error;
    }

    /// <summary>Gets whether the operation succeeded.</summary>
    public bool IsOk => Status == ScepClientResult.Ok;

    /// <summary>Creates a successful result wrapping the given value.</summary>
    public static ScepResult<T> Ok(T value) => new(ScepClientResult.Ok, value, string.Empty);

    /// <summary>Creates a failed result with the given status and error.</summary>
    public static ScepResult<T> Fail(ScepClientResult status, string error) =>
        new(status, default!, error);

    /// <summary>Creates a failed result that still carries a partial value (e.g. Pending).</summary>
    public static ScepResult<T> Fail(ScepClientResult status, T value, string error) =>
        new(status, value, error);
}
