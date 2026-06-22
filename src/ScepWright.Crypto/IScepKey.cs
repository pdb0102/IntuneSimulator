namespace ScepWright.Crypto;

/// <summary>An opaque handle to a key pair held by a crypto provider.</summary>
public interface IScepKey {
    /// <summary>Gets the OID of the key's algorithm.</summary>
    string AlgorithmOid { get; }
    /// <summary>Gets the key size in bits (0 for PQ parameter-set keys).</summary>
    int SizeBits { get; }
}
