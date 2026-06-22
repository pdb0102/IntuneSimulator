namespace ScepWright.Core.Testing;

/// <summary>Tunable thresholds for the security opinion engine.</summary>
public sealed class OpinionThresholds {
    /// <summary>Gets the minimum acceptable RSA key size in bits. Defaults to 2048.</summary>
    public int MinRsaKeyBits { get; init; } = 2048;
}
