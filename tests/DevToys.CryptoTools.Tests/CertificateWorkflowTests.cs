using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Tests;

public class CertificateWorkflowTests
{
    [Theory]
    [InlineData("RSA-2048")]
    [InlineData("ECDSA-P256")]
    [InlineData("SM2")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    public void ImportedKeyPairCreatesVerifiableCsrWithEverySanType(string algorithm)
    {
        var keys = KeyGenerator.Generate(algorithm);
        var options = new CertificateOptions
        {
            Algorithm = algorithm, PrivateKeyPem = keys.PrivateKey, PublicKeyPem = keys.PublicKey,
            Subject = "CN=example.test,O=Example,OU=Engineering,C=CN,ST=Guangdong,L=Shenzhen",
            DnsNames = ["example.test", "*.example.test"], IpAddresses = ["127.0.0.1", "::1"],
            EmailAddresses = ["alice@example.test"], Uris = ["https://example.test/identity"],
            EnhancedKeyUsageOids = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
            SanCritical = true
        };
        var material = CertificateRequestService.Generate(options);
        Assert.Equal(keys.PrivateKey, material.PrivateKey);
        var request = CertificateRequestService.Parse(Encoding.UTF8.GetBytes(material.Document));
        Assert.True(request.Verify());
        Assert.Equal(keys.PublicKey, CertificateRequestService.Inspect(request.GetDerEncoded()).PublicKeyPem);
        var details = CertificateRequestService.Inspect(Encoding.UTF8.GetBytes(material.Document));
        Assert.Equal(options.DnsNames, details.DnsNames);
        Assert.Equal(options.IpAddresses, details.IpAddresses);
        Assert.Equal(options.EmailAddresses, details.EmailAddresses);
        Assert.Equal(options.Uris, details.Uris);
        Assert.Equal(material.Document, CertificateRequestService.Normalize(request.GetDerEncoded()));
    }

    [Fact]
    public void CsrRejectsUnrelatedPublicKeyAndInvalidSignature()
    {
        var keys = KeyGenerator.Generate("ECDSA-P256");
        var unrelated = KeyGenerator.Generate("ECDSA-P256");
        Assert.Throws<ArgumentException>(() => CertificateRequestService.Generate(new CertificateOptions
        {
            PrivateKeyPem = keys.PrivateKey, PublicKeyPem = unrelated.PublicKey
        }));
        var material = CertificateRequestService.Generate(new CertificateOptions { PrivateKeyPem = keys.PrivateKey });
        byte[] der = CertificateRequestService.Parse(Encoding.UTF8.GetBytes(material.Document)).GetDerEncoded();
        der[^1] ^= 1;
        Assert.Throws<ArgumentException>(() => CertificateRequestService.Parse(der));
        Assert.Throws<ArgumentException>(() => CertificateRequestService.Generate(new CertificateOptions
        {
            Algorithm = "X25519", PrivateKeyPem = KeyGenerator.Generate("X25519").PrivateKey
        }));
    }

    [Fact]
    public void CaSignsCsrAndUsesExplicitExtensionsInsteadOfRequestedPrivileges()
    {
        var now = DateTime.UtcNow;
        var ca = CertificateGenerator.Generate(new CertificateOptions
        {
            Algorithm = "ECDSA-P256", Subject = "CN=Test CA", IsCa = true, PathLength = 1,
            KeyUsage = KeyUsage.KeyCertSign | KeyUsage.CrlSign, NotBeforeUtc = now.AddDays(-1), NotAfterUtc = now.AddDays(366)
        });
        var request = CertificateRequestService.Generate(new CertificateOptions
        {
            Algorithm = "SM2", Subject = "CN=Requested CA", IsCa = true, PathLength = 100,
            KeyUsage = KeyUsage.KeyCertSign | KeyUsage.CrlSign, DnsNames = ["csr.example.test"]
        });
        var leaf = CertificateGenerator.Generate(new CertificateOptions
        {
            CsrPem = request.Document, Subject = "CN=Issued leaf", IssuerCertificatePem = ca.Document, IssuerPrivateKeyPem = ca.PrivateKey,
            SerialHex = "1234", NotBeforeUtc = now, NotAfterUtc = now.AddDays(30), DnsNames = ["issued.example.test"],
            KeyUsage = KeyUsage.DigitalSignature, EnhancedKeyUsageOids = ["1.3.6.1.5.5.7.3.1"],
            CustomExtensions = [new("1.2.3.4.5", true, Convert.ToBase64String(new DerUtf8String("custom").GetDerEncoded()))]
        });
        var issuerCert = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(ca.Document));
        var certificate = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(leaf.Document));
        certificate.Verify(issuerCert.GetPublicKey());
        Assert.Equal(issuerCert.SubjectDN, certificate.IssuerDN);
        Assert.Equal(-1, certificate.GetBasicConstraints());
        Assert.False(certificate.GetKeyUsage()[5]);
        Assert.Equal("1234", certificate.SerialNumber.ToString(16));
        Assert.Empty(leaf.PrivateKey);
        Assert.NotNull(certificate.GetExtensionParsedValue(X509Extensions.SubjectKeyIdentifier));
        Assert.Equal("custom", DerUtf8String.GetInstance(certificate.GetExtensionParsedValue(new DerObjectIdentifier("1.2.3.4.5"))).GetString());
        Assert.NotNull(certificate.GetExtensionParsedValue(X509Extensions.AuthorityKeyIdentifier));
        var names = GeneralNames.GetInstance(certificate.GetExtensionParsedValue(X509Extensions.SubjectAlternativeName)).GetNames();
        Assert.Single(names);
        Assert.Equal("issued.example.test", DerIA5String.GetInstance(names[0].Name).GetString());
    }

    [Fact]
    public void CsrCanSelfSignOnlyWithItsMatchingPrivateKey()
    {
        var keys = KeyGenerator.Generate("Ed25519");
        var csr = CertificateRequestService.Generate(new CertificateOptions { PrivateKeyPem = keys.PrivateKey, Subject = "CN=ed" });
        var certificate = CertificateGenerator.Generate(new CertificateOptions { CsrPem = csr.Document, PrivateKeyPem = keys.PrivateKey, Subject = "" });
        var parsed = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(certificate.Document));
        parsed.Verify(parsed.GetPublicKey());
        Assert.Equal("CN=ed", parsed.SubjectDN.ToString());
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(new CertificateOptions { CsrPem = csr.Document }));
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(new CertificateOptions
        {
            CsrPem = csr.Document, PrivateKeyPem = KeyGenerator.Generate("Ed25519").PrivateKey
        }));
    }

    [Fact]
    public void IssuingRejectsNonCaWrongIssuerKeyAndOutOfRangeValidity()
    {
        var now = DateTime.UtcNow;
        var leafIssuer = CertificateGenerator.Generate(new CertificateOptions { Algorithm = "ECDSA-P256", NotBeforeUtc = now.AddDays(-1), NotAfterUtc = now.AddDays(40) });
        var ca = CertificateGenerator.Generate(new CertificateOptions
        {
            Algorithm = "ECDSA-P256", IsCa = true, KeyUsage = KeyUsage.KeyCertSign,
            NotBeforeUtc = now.AddDays(-1), NotAfterUtc = now.AddDays(40)
        });
        var csr = CertificateRequestService.Generate(new CertificateOptions { Algorithm = "SM2" });
        var options = new CertificateOptions
        {
            CsrPem = csr.Document, IssuerCertificatePem = ca.Document, IssuerPrivateKeyPem = ca.PrivateKey,
            NotBeforeUtc = now, NotAfterUtc = now.AddDays(30)
        };
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(options with { IssuerCertificatePem = leafIssuer.Document, IssuerPrivateKeyPem = leafIssuer.PrivateKey }));
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(options with { IssuerPrivateKeyPem = leafIssuer.PrivateKey }));
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(options with { NotAfterUtc = now.AddDays(50) }));
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(options with { Issuer = "CN=Impostor" }));
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(options with { IsCa = true, PathLength = -1 }));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
    [InlineData("xyz")]
    public void RejectsInvalidSerials(string hex) => Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(new CertificateOptions { Algorithm = "Ed25519", SerialHex = hex }));

    [Fact]
    public void EveryUsageBitAndCustomEkuCanBeEncoded()
    {
        var options = new CertificateOptions
        {
            Algorithm = "ECDSA-P256", IsCa = true, PathLength = 0,
            KeyUsage = KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment
                | KeyUsage.KeyAgreement | KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.EncipherOnly | KeyUsage.DecipherOnly,
            EnhancedKeyUsageOids = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4",
                "1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9", "1.3.6.1.4.1.311.10.3.12", "1.2.3.4.99"], EnhancedKeyUsageCritical = true
        };
        var result = CertificateGenerator.Generate(options);
        var cert = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(result.Document));
        Assert.Equal(0, cert.GetBasicConstraints());
        Assert.All(cert.GetKeyUsage().Take(9), bit => Assert.True(bit));
        Assert.Equal(8, cert.GetExtendedKeyUsage().Count);
        Assert.True(cert.GetExtension(X509Extensions.ExtendedKeyUsage).IsCritical);
    }

    [Fact]
    public void RsaPssCertificatesAndCsrUseChosenDigest()
    {
        var options = new CertificateOptions { Algorithm = "RSA-2048", HashAlgorithm = "SHA384", RsaPss = true };
        var csr = CertificateRequestService.Generate(options);
        Assert.True(CertificateRequestService.Parse(Encoding.UTF8.GetBytes(csr.Document)).Verify());
        var result = CertificateGenerator.Generate(options);
        var cert = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(result.Document));
        cert.Verify(cert.GetPublicKey());
        Assert.Equal("1.2.840.113549.1.1.10", cert.SigAlgOid);
    }

    [Fact]
    public void IssuerSignatureSettingsDoNotConstrainTheSubjectKeyType()
    {
        var now = DateTime.UtcNow;
        var ca = CertificateGenerator.Generate(new CertificateOptions
        {
            Algorithm = "RSA-2048", IsCa = true, KeyUsage = KeyUsage.KeyCertSign,
            NotBeforeUtc = now.AddDays(-1), NotAfterUtc = now.AddDays(100)
        });
        var key = KeyGenerator.Generate("Ed25519");
        var cert = CertificateGenerator.Generate(new CertificateOptions
        {
            PrivateKeyPem = key.PrivateKey, IssuerCertificatePem = ca.Document, IssuerPrivateKeyPem = ca.PrivateKey,
            HashAlgorithm = "SHA384", RsaPss = true, NotBeforeUtc = now, NotAfterUtc = now.AddDays(10)
        });
        var parsed = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(cert.Document));
        parsed.Verify(CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(ca.Document)).GetPublicKey());
        Assert.Equal(key.PublicKey, CertificateRequestService.ExportPublic(parsed.GetPublicKey()));
    }

    [Fact]
    public void CsrIssuingRejectsAnExplicitUnrelatedPublicKey()
    {
        var ca = CertificateGenerator.Generate(new CertificateOptions
        {
            Algorithm = "Ed25519", IsCa = true, KeyUsage = KeyUsage.KeyCertSign,
            NotBeforeUtc = DateTime.UtcNow.AddDays(-1), NotAfterUtc = DateTime.UtcNow.AddDays(400)
        });
        var csr = CertificateRequestService.Generate(new CertificateOptions { Algorithm = "ECDSA-P256" });
        var unrelated = KeyGenerator.Generate("ECDSA-P256");
        Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate(new CertificateOptions
        {
            CsrPem = csr.Document, PublicKeyPem = unrelated.PublicKey,
            IssuerCertificatePem = ca.Document, IssuerPrivateKeyPem = ca.PrivateKey
        }));
    }

    [Fact]
    public void SignedCsrWithMalformedSanIsRejectedDuringInspection()
    {
        var options = new CertificateOptions { Algorithm = "Ed25519" };
        var material = CertificateRequestService.GetKeyMaterial(options);
        var extensions = new X509ExtensionsGenerator();
        // The CSR is correctly signed, but SAN must be GeneralNames rather than an INTEGER.
        extensions.AddExtension(X509Extensions.SubjectAlternativeName, false, DerInteger.ValueOf(123));
        var attribute = new Org.BouncyCastle.Asn1.Pkcs.AttributePkcs(
            Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions.Generate()));
        var request = new Pkcs10CertificationRequest(CertificateRequestService.SignatureFactory(material.Private, options),
            new X509Name("CN=malformed"), material.Public, new DerSet(attribute));
        Assert.True(request.Verify());
        var error = Assert.Throws<ArgumentException>(() => CertificateRequestService.Inspect(request.GetDerEncoded()));
        Assert.Equal(DevToys.CryptoTools.Localization.Text.L("InvalidCsr"), error.Message);
    }

    [Fact]
    public void CsrInspectionPreservesEditableRequestedExtensions()
    {
        var options = new CertificateOptions
        {
            Algorithm = "Ed25519", IsCa = true, PathLength = 2, BasicConstraintsCritical = false,
            KeyUsage = KeyUsage.KeyCertSign | KeyUsage.CrlSign, KeyUsageCritical = false,
            EnhancedKeyUsageOids = ["1.3.6.1.5.5.7.3.1", "1.2.3.4.123"], EnhancedKeyUsageCritical = true,
            SanCritical = true, DnsNames = ["example.test"], IpAddresses = ["::1"],
            CustomExtensions = [new("1.2.3.4.5", false, "AgEB"), new("1.2.3.4.6", true, "AgEC")]
        };
        var request = CertificateRequestService.Generate(options);
        var details = CertificateRequestService.Inspect(Encoding.UTF8.GetBytes(request.Document));
        var inspected = Assert.IsType<CertificateOptions>(details.RequestedOptions);
        Assert.Equal(options.IsCa, inspected.IsCa);
        Assert.Equal(options.PathLength, inspected.PathLength);
        Assert.Equal(options.BasicConstraintsCritical, inspected.BasicConstraintsCritical);
        Assert.Equal(options.KeyUsage, inspected.KeyUsage);
        Assert.Equal(options.KeyUsageCritical, inspected.KeyUsageCritical);
        Assert.Equal(options.EnhancedKeyUsageOids, inspected.EnhancedKeyUsageOids);
        Assert.Equal(options.EnhancedKeyUsageCritical, inspected.EnhancedKeyUsageCritical);
        Assert.Equal(options.SanCritical, inspected.SanCritical);
        Assert.Equal(options.DnsNames, inspected.DnsNames);
        Assert.Equal(options.IpAddresses, inspected.IpAddresses);
        Assert.Equal(options.CustomExtensions, inspected.CustomExtensions);
    }
}
