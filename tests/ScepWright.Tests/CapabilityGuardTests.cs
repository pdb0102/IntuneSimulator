using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using Xunit;

namespace ScepWright.Tests;

public sealed class CapabilityGuardTests {
    private const string OidAes128 = "2.16.840.1.101.3.4.1.2";
    private const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    private const string OidRsa = "1.2.840.113549.1.1.1";
    private const string OidEc = "1.2.840.10045.2.1";

    private static CryptoCapabilities Bc() => new BouncyCastleScepCrypto().Capabilities;

    [Fact]
    public void Mlkem_recipient_passes_under_capable_provider() {
        PkiMessage message;
        string error;

        message = new PkiMessage {
            RecipientCaCert = TestCertFactory.Make("ml-kem", KeyUsage.KeyEncipherment),
            ContentEncryptionAlgorithmOid = OidAes128,
        };
        Assert.True(CapabilityGuard.Check(message, Bc(), out error), error);
    }

    [Fact]
    public void Ec_recipient_passes_under_capable_provider() {
        PkiMessage message;
        string error;

        message = new PkiMessage {
            RecipientCaCert = TestCertFactory.Make("ec", KeyUsage.KeyAgreement),
            ContentEncryptionAlgorithmOid = OidAes128,
        };
        Assert.True(CapabilityGuard.Check(message, Bc(), out error), error);
    }

    [Fact]
    public void Mlkem_recipient_fails_cleanly_when_kem_unsupported() {
        CryptoCapabilities caps;
        PkiMessage message;
        string error;

        caps = new CryptoCapabilities {
            ContentEncryption = new[] { OidAes128 },
            KeyTransport = new[] { OidRsa },
            KeyAgreement = new[] { OidEc },
            Kem = Array.Empty<string>(),
        };
        message = new PkiMessage {
            RecipientCaCert = TestCertFactory.Make("ml-kem", KeyUsage.KeyEncipherment),
            ContentEncryptionAlgorithmOid = OidAes128,
        };
        Assert.False(CapabilityGuard.Check(message, caps, out error));
        Assert.Contains("ML-KEM", error);
    }

    [Fact]
    public void Ec_recipient_fails_cleanly_when_keyagreement_unsupported() {
        CryptoCapabilities caps;
        PkiMessage message;
        string error;

        caps = new CryptoCapabilities {
            ContentEncryption = new[] { OidAes128 },
            KeyTransport = new[] { OidRsa },
            KeyAgreement = Array.Empty<string>(),
        };
        message = new PkiMessage {
            RecipientCaCert = TestCertFactory.Make("ec", KeyUsage.KeyAgreement),
            ContentEncryptionAlgorithmOid = OidAes128,
        };
        Assert.False(CapabilityGuard.Check(message, caps, out error));
        Assert.Contains("EC", error);
    }

    [Fact]
    public void Signer_fails_cleanly_when_digest_unsupported() {
        CryptoCapabilities caps;
        PkiMessage message;
        string error;

        caps = new CryptoCapabilities {
            Digests = Array.Empty<string>(),
            Signatures = new[] { OidRsa },
        };
        message = new PkiMessage {
            SignerCert = TestCertFactory.Make("rsa", KeyUsage.DigitalSignature),
            DigestAlgorithmOid = OidSha256,
        };
        Assert.False(CapabilityGuard.Check(message, caps, out error));
        Assert.Contains("digest", error);
    }
}
