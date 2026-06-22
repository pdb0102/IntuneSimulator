using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using ScepWright.Core.Recipients;
using ScepWright.Tests.Fakes;
using Xunit;

namespace ScepWright.Tests;

// An expired / not-yet-valid recipient cert must downgrade the verdict, not read as OK.
public sealed class RecipientHealthTests {
    [Fact]
    public void Valid_recipient_has_no_temporal_warnings() {
        X509Certificate2 cert;

        cert = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment);
        Assert.Empty(RecipientHealth.TemporalWarnings(cert));
    }

    [Fact]
    public void Expired_recipient_is_flagged() {
        X509Certificate2 cert;

        cert = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment, DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddYears(-1));
        Assert.Contains(RecipientHealth.TemporalWarnings(cert), w => w.Contains("EXPIRED"));
    }

    [Fact]
    public void Not_yet_valid_recipient_is_flagged() {
        X509Certificate2 cert;

        cert = TestCertFactory.Make("rsa", KeyUsage.KeyEncipherment, DateTime.UtcNow.AddDays(5), DateTime.UtcNow.AddYears(1));
        Assert.Contains(RecipientHealth.TemporalWarnings(cert), w => w.Contains("NOT YET VALID"));
    }
}
