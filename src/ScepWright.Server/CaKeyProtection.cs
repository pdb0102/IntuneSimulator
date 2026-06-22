using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace ScepWright.Server;

/// <summary>
/// Raised when an encrypted CA/RA key cannot be unprotected (wrong/empty passphrase, missing passphrase
/// for an encrypted key, or a malformed encrypted blob). The host turns this into a one-line message and
/// a non-zero exit code rather than letting a BouncyCastle stack trace escape.
/// </summary>
public sealed class CaKeyProtectionException : Exception {
    /// <summary>Initializes a new instance with the specified message.</summary>
    public CaKeyProtectionException(string message) : base(message) { }
    /// <summary>Initializes a new instance with the specified message and inner exception.</summary>
    public CaKeyProtectionException(string message, Exception inner) : base(message, inner) { }
}

// At-rest protection for the standalone SCEP CA's private keys. The server does its OWN crypto (it does
// not reference ScepWright.Crypto), so this reimplements the same PBES2 scheme the client uses:
// PBKDF2-HMAC-SHA256 (~100k iters) deriving an AES-256-CBC key, assembled from BouncyCastle primitives
// because BC's Pkcs8Generator only offers the legacy PBES1 SHA-1/3DES profile. Decryption accepts any
// standard PBES1/PBES2 scheme on read.
internal static class CaKeyProtection {
    private const int IterationCount = 100_000;

    public static byte[] Encrypt(AsymmetricKeyParameter private_key, string passphrase) {
        byte[] salt;
        byte[] iv;
        byte[] plain;
        SecureRandom random;
        Pkcs5S2ParametersGenerator kdf_gen;
        KeyParameter derived;
        IBufferedCipher cipher;
        byte[] encrypted;
        AlgorithmIdentifier prf;
        DerSequence pbkdf2_params;
        AlgorithmIdentifier kdf_alg;
        AlgorithmIdentifier enc_scheme;
        DerSequence pbes2_params;
        AlgorithmIdentifier alg_id;
        EncryptedPrivateKeyInfo enc_info;

        random = new SecureRandom();
        salt = new byte[16];
        iv = new byte[16];
        random.NextBytes(salt);
        random.NextBytes(iv);

        plain = PrivateKeyInfoFactory.CreatePrivateKeyInfo(private_key).GetDerEncoded();

        kdf_gen = new Pkcs5S2ParametersGenerator(new Sha256Digest());
        kdf_gen.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(passphrase.ToCharArray()), salt, IterationCount);
        derived = (KeyParameter)kdf_gen.GenerateDerivedParameters("AES", 256);

        cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
        cipher.Init(true, new ParametersWithIV(derived, iv));
        encrypted = cipher.DoFinal(plain);

        prf = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha256, DerNull.Instance);
        pbkdf2_params = new DerSequence(new DerOctetString(salt), new DerInteger(IterationCount), prf);
        kdf_alg = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbkdf2, pbkdf2_params);
        enc_scheme = new AlgorithmIdentifier(NistObjectIdentifiers.IdAes256Cbc, new DerOctetString(iv));
        pbes2_params = new DerSequence(kdf_alg, enc_scheme);
        alg_id = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, pbes2_params);

        enc_info = new EncryptedPrivateKeyInfo(alg_id, encrypted);
        return enc_info.GetEncoded();
    }

    public static AsymmetricKeyParameter Decrypt(byte[] der, string? passphrase) {
        EncryptedPrivateKeyInfo enc_info;

        if (string.IsNullOrEmpty(passphrase)) {
            throw new CaKeyProtectionException("CA key on disk is encrypted but no passphrase was provided");
        }

        try {
            enc_info = EncryptedPrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(der));
            return PrivateKeyFactory.DecryptKey(passphrase.ToCharArray(), enc_info);
        } catch (Exception ex) {
            throw new CaKeyProtectionException("could not decrypt CA key with the provided passphrase (wrong passphrase?)", ex);
        }
    }
}
