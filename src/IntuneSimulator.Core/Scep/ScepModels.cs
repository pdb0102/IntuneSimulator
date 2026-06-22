using System.Text.Json.Serialization;

namespace IntuneSimulator.Core.Scep;

/// <summary>Envelope for a SCEP validation request.</summary>
public sealed class ScepValidateBody { /// <summary>Gets or sets the validation request payload.</summary>
public ScepValidateRequest? Request { get; set; } }

/// <summary>Payload sent to the SCEP validation endpoint.</summary>
public sealed class ScepValidateRequest
{
    /// <summary>Gets or sets the SCEP transaction id.</summary>
    public string? TransactionId { get; set; }
    /// <summary>Gets or sets the encoded certificate request (CSR).</summary>
    public string? CertificateRequest { get; set; }
    /// <summary>Gets or sets caller diagnostic information.</summary>
    public string? CallerInfo { get; set; }
}

/// <summary>Envelope for a SCEP success notification.</summary>
public sealed class ScepSuccessBody { /// <summary>Gets or sets the success notification payload.</summary>
public ScepSuccessNotification? Notification { get; set; } }

/// <summary>Notification that a SCEP certificate was issued successfully.</summary>
public sealed class ScepSuccessNotification
{
    /// <summary>Gets or sets the SCEP transaction id.</summary>
    public string? TransactionId { get; set; }
    /// <summary>Gets or sets the encoded certificate request (CSR).</summary>
    public string? CertificateRequest { get; set; }
    /// <summary>Gets or sets the issued certificate thumbprint.</summary>
    public string? CertificateThumbprint { get; set; }
    /// <summary>Gets or sets the issued certificate serial number.</summary>
    public string? CertificateSerialNumber { get; set; }
    /// <summary>Gets or sets the issued certificate expiration time (UTC).</summary>
    public string? CertificateExpirationDateUtc { get; set; }
    /// <summary>Gets or sets the issuing certificate authority.</summary>
    public string? IssuingCertificateAuthority { get; set; }
    /// <summary>Gets or sets caller diagnostic information.</summary>
    public string? CallerInfo { get; set; }
    /// <summary>Gets or sets the CA configuration identifier.</summary>
    public string? CaConfiguration { get; set; }
    /// <summary>Gets or sets the certificate authority name.</summary>
    public string? CertificateAuthority { get; set; }
}

/// <summary>Envelope for a SCEP failure notification.</summary>
public sealed class ScepFailureBody { /// <summary>Gets or sets the failure notification payload.</summary>
public ScepFailureNotification? Notification { get; set; } }

/// <summary>Notification that a SCEP certificate issuance failed.</summary>
public sealed class ScepFailureNotification
{
    /// <summary>Gets or sets the SCEP transaction id.</summary>
    public string? TransactionId { get; set; }
    /// <summary>Gets or sets the encoded certificate request (CSR).</summary>
    public string? CertificateRequest { get; set; }
    /// <summary>Gets or sets the failure HRESULT.</summary>
    public long HResult { get; set; }
    /// <summary>Gets or sets the human-readable error description.</summary>
    public string? ErrorDescription { get; set; }
    /// <summary>Gets or sets caller diagnostic information.</summary>
    public string? CallerInfo { get; set; }
}

/// <summary>Result returned from the SCEP validation endpoint.</summary>
public sealed class ScepResult
{
    /// <summary>Gets or sets the SCEP result code name.</summary>
    [JsonPropertyName("code")] public string Code { get; set; } = "Success";
    /// <summary>Gets or sets the error description, empty on success.</summary>
    [JsonPropertyName("errorDescription")] public string ErrorDescription { get; set; } = "";
}

/// <summary>Valid SCEP error-code names (from IntuneScepServiceException.ErrorCode) for canned responses.</summary>
public static class ScepErrorCodes
{
    /// <summary>Gets all valid SCEP error-code names.</summary>
    public static readonly string[] All =
    {
        "Success","CertificateRequestDecodingFailed","ChallengePasswordMissing","ChallengeDeserializationError",
        "ChallengeDecryptionError","ChallengeDecodingError","ChallengeInvalidTimestamp","ChallengeExpired",
        "SubjectNameMissing","SubjectNameMismatch","SubjectAltNameMissing","SubjectAltNameMismatch",
        "KeyUsageMismatch","KeyLengthMismatch","EnhancedKeyUsageMissing","EnhancedKeyUsageMismatch",
        "AadKeyIdentifierListMissing","RegisteredKeyMismatch","SigningCertThumbprintMismatch",
        "ScepProfileNoLongerTargetedToTheClient","SignatureValidationFailed","BadCertificateRequestIdInChallenge",
        "BadDeviceIdInChallenge","BadUserIdInChallenge"
    };
}
