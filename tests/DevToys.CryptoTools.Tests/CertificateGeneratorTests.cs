using System.Security.Cryptography;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Tests;

public class CertificateGeneratorTests
{
    public static IEnumerable<object[]> Algorithms => CertificateGenerator.Algorithms.Select(a => new object[] { a });

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void SelfSignedCertificateHasValidSignatureAndMatchingKey(string algorithm)
    {
        var result = CertificateGenerator.Generate(algorithm, "CN=localhost,O=CryptoTools", "localhost,example.test", 30, false);
        var cert = new X509CertificateParser().ReadCertificate(Decode(result.Document));
        cert.Verify(cert.GetPublicKey());
        Assert.Equal(cert.SubjectDN, cert.IssuerDN);
        Assert.NotNull(cert.GetSubjectAlternativeNames());
        Assert.Equal(-1, cert.GetBasicConstraints());
        Assert.InRange(cert.SerialNumber.ToByteArray().Length, 1, 20);
        Assert.True(cert.SerialNumber.SignValue > 0);
        Assert.InRange((cert.NotAfter - cert.NotBefore).TotalDays, 30, 31);
        Assert.True(KeyGenerator.ReadKey(result.PrivateKey, true).IsPrivate);
        var signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner(cert.SigAlgName);
        signer.Init(true, KeyGenerator.ReadKey(result.PrivateKey, true));
        signer.BlockUpdate(new byte[] { 1, 2, 3 }, 0, 3);
        var signature = signer.GenerateSignature();
        signer.Init(false, cert.GetPublicKey());
        signer.BlockUpdate(new byte[] { 1, 2, 3 }, 0, 3);
        Assert.True(signer.VerifySignature(signature));
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void CsrSignatureAndSanAreValid(string algorithm)
    {
        var result = CertificateGenerator.Generate(algorithm, "CN=localhost", "localhost", 30, true);
        var csr = new Pkcs10CertificationRequest(Decode(result.Document));
        Assert.True(csr.Verify());
        Assert.NotNull(csr.GetRequestedExtensions().GetExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectAlternativeName));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3651)]
    public void RejectsInvalidValidity(int days) => Assert.Throws<ArgumentException>(() => CertificateGenerator.Generate("SM2", "CN=test", "", days, false));

    private static byte[] Decode(string pem) => Convert.FromBase64String(pem[PemEncoding.Find(pem).Base64Data]);
}
