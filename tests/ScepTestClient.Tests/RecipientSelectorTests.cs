using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using ScepTestClient.Core.Recipients;
using ScepTestClient.Tests.Fakes;
using Xunit;

namespace ScepTestClient.Tests;

public sealed class RecipientSelectorTests {
    [Theory]
    [InlineData("1.2.840.113549.1.1.1", RecipientKind.KeyTransport)]
    [InlineData("1.2.840.10045.2.1", RecipientKind.KeyAgreement)]
    [InlineData("2.16.840.1.101.3.4.4.2", RecipientKind.Kem)]
    [InlineData("2.16.840.1.101.3.4.3.18", RecipientKind.SignatureOnly)]
    [InlineData("1.3.6.1.4.1.99999", RecipientKind.Unknown)]
    public void Classifies_algorithm_by_oid(string oid, RecipientKind expected) {
        Assert.Equal(expected, RecipientSelector.ClassifyAlgorithm(oid));
    }

    [Fact]
    public void Single_dual_use_rsa_is_signing_and_encryption() {
        X509Certificate2 cert;
        RecipientSelection selection;

        cert = TestCertFactory.Make("rsa", KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment);
        selection = RecipientSelector.Select(new[] { cert });

        Assert.True(selection.CanEnvelope);
        Assert.Equal(RecipientKind.KeyTransport, selection.EncryptionKind);
        Assert.Same(cert, selection.EncryptionCertificate);
        Assert.Same(cert, selection.SigningCertificate);
        Assert.DoesNotContain(selection.Findings, f => f.Code == "no-encryption-cert");
    }

    [Fact]
    public void Single_dual_use_ec_uses_key_agreement() {
        X509Certificate2 cert;
        RecipientSelection selection;

        cert = TestCertFactory.Make("ec", KeyUsage.DigitalSignature | KeyUsage.KeyAgreement);
        selection = RecipientSelector.Select(new[] { cert });

        Assert.True(selection.CanEnvelope);
        Assert.Equal(RecipientKind.KeyAgreement, selection.EncryptionKind);
    }

    [Fact]
    public void Signature_only_ca_cannot_envelope() {
        X509Certificate2 cert;
        RecipientSelection selection;

        cert = TestCertFactory.Make("ml-dsa", KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
        selection = RecipientSelector.Select(new[] { cert });

        Assert.False(selection.CanEnvelope);
        Assert.Null(selection.EncryptionCertificate);
        Assert.Contains(selection.Findings, f => f.Code == "no-encryption-cert");
    }

    [Fact]
    public void Split_mldsa_sign_rsa_encrypt() {
        X509Certificate2 sign;
        X509Certificate2 enc;
        RecipientSelection selection;

        sign = TestCertFactory.Make("ml-dsa", KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
        enc = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment);
        selection = RecipientSelector.Select(new[] { sign, enc });

        Assert.True(selection.CanEnvelope);
        Assert.Same(enc, selection.EncryptionCertificate);
        Assert.Same(sign, selection.SigningCertificate);
        Assert.Equal(RecipientKind.KeyTransport, selection.EncryptionKind);
    }

    [Fact]
    public void Split_mldsa_sign_mlkem_encrypt() {
        X509Certificate2 sign;
        X509Certificate2 enc;
        RecipientSelection selection;

        sign = TestCertFactory.Make("ml-dsa", KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
        enc = TestCertFactory.Make("ml-kem", KeyUsage.KeyEncipherment);
        selection = RecipientSelector.Select(new[] { sign, enc });

        Assert.True(selection.CanEnvelope);
        Assert.Equal(RecipientKind.Kem, selection.EncryptionKind);
        Assert.Same(enc, selection.EncryptionCertificate);
    }

    [Fact]
    public void Encryption_capable_key_without_keyusage_bit_is_flagged() {
        X509Certificate2 sign;
        X509Certificate2 enc;
        RecipientSelection selection;

        // RSA key, but the operator forgot to set keyEncipherment (only digitalSignature).
        sign = TestCertFactory.Make("ml-dsa", KeyUsage.DigitalSignature | KeyUsage.KeyCertSign);
        enc = TestCertFactory.Make("rsa", KeyUsage.DigitalSignature);
        selection = RecipientSelector.Select(new[] { sign, enc });

        Assert.False(selection.CanEnvelope);
        Assert.Contains(selection.Findings, f => f.Code == "encryption-keyusage-missing");
    }

    [Fact]
    public void Positional_strategy_picks_second_cert() {
        X509Certificate2 sign;
        X509Certificate2 enc;
        RecipientSelection selection;

        sign = TestCertFactory.Make("ec", KeyUsage.DigitalSignature);
        enc = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment);
        selection = RecipientSelector.Select(new[] { sign, enc }, RecipientStrategy.Positional);

        Assert.Same(enc, selection.EncryptionCertificate);
        Assert.Equal(RecipientKind.KeyTransport, selection.EncryptionKind);
    }
}
