namespace ScepWright.Crypto;

/// <summary>The coarse outcome category of a SCEP client operation.</summary>
public enum ScepClientResult {
    /// <summary>The operation succeeded.</summary>
    Ok = 0,
    /// <summary>A caller-supplied argument was invalid.</summary>
    InvalidArgument,
    /// <summary>A transport/network error occurred.</summary>
    NetworkError,
    /// <summary>The peer violated the SCEP protocol.</summary>
    ProtocolError,
    /// <summary>A cryptographic operation failed.</summary>
    CryptoError,
    /// <summary>The server returned a SCEP FAILURE response.</summary>
    ServerFailure,
    /// <summary>The request is pending CA approval.</summary>
    Pending,
    /// <summary>The requested object was not found.</summary>
    NotFound,
    /// <summary>The loaded crypto provider failed or lacks a capability.</summary>
    ProviderError,
}
