using System.Text.Json.Serialization;

namespace IntuneSimulator.Core.Scep;

public sealed class ScepValidateBody { public ScepValidateRequest? Request { get; set; } }
public sealed class ScepValidateRequest
{
    public string? TransactionId { get; set; }
    public string? CertificateRequest { get; set; }
    public string? CallerInfo { get; set; }
}

public sealed class ScepSuccessBody { public ScepSuccessNotification? Notification { get; set; } }
public sealed class ScepSuccessNotification
{
    public string? TransactionId { get; set; }
    public string? CertificateRequest { get; set; }
    public string? CertificateThumbprint { get; set; }
    public string? CertificateSerialNumber { get; set; }
    public string? CertificateExpirationDateUtc { get; set; }
    public string? IssuingCertificateAuthority { get; set; }
    public string? CallerInfo { get; set; }
    public string? CaConfiguration { get; set; }
    public string? CertificateAuthority { get; set; }
}

public sealed class ScepFailureBody { public ScepFailureNotification? Notification { get; set; } }
public sealed class ScepFailureNotification
{
    public string? TransactionId { get; set; }
    public string? CertificateRequest { get; set; }
    public long HResult { get; set; }
    public string? ErrorDescription { get; set; }
    public string? CallerInfo { get; set; }
}

public sealed class ScepResult
{
    [JsonPropertyName("code")] public string Code { get; set; } = "Success";
    [JsonPropertyName("errorDescription")] public string ErrorDescription { get; set; } = "";
}

/// <summary>Valid SCEP error-code names (from IntuneScepServiceException.ErrorCode) for canned responses.</summary>
public static class ScepErrorCodes
{
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
