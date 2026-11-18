using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevToys.CryptoTools.Tests;

public class EllipticCurveKeyImportTests
{
    public static IEnumerable<object[]> CoordinateAlgorithms => EllipticCurveKeyImport.CoordinateAlgorithms.Select(algorithm => new object[] { algorithm });
    [Theory]
    [InlineData("ECDSA-P256")]
    [InlineData("ECDSA-P384")]
    [InlineData("ECDSA-P521")]
    [InlineData("SM2")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    public void ExtractsPublicKeysFromPemAndDerCertificates(string algorithm)
    {
        var certificate = CertificateGenerator.Generate(algorithm, "CN=test", "", 1, false);
        string signature = EllipticCurveCryptography.Sign(algorithm, certificate.PrivateKey, "message");
        foreach (byte[] input in new[] { Encoding.UTF8.GetBytes(certificate.Document), Der(certificate.Document) })
        {
            string publicKey = EllipticCurveKeyImport.Import(input);
            Assert.True(EllipticCurveCryptography.Verify(algorithm, publicKey, "message", signature));
            Assert.Contains("BEGIN PUBLIC KEY", publicKey);
        }
    }

    [Theory]
    [InlineData("ECDSA-P256")]
    [InlineData("SM2")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    [InlineData("X25519")]
    public void ImportsPublicAndPrivatePemAndDerKeys(string algorithm)
    {
        var keys = KeyGenerator.Generate(algorithm);
        foreach (string pem in new[] { keys.PublicKey, keys.PrivateKey })
        {
            foreach (byte[] input in new[] { Encoding.UTF8.GetBytes(pem), Der(pem) })
            {
                string normalized = EllipticCurveKeyImport.Import(input);
                Assert.Equal(pem, normalized);
            }
        }
    }

    [Fact]
    public void NormalizesSec1PrivateKeysToPkcs8()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        foreach (byte[] input in new[] { key.ExportECPrivateKey(), Encoding.UTF8.GetBytes(key.ExportECPrivateKeyPem()) })
        {
            string normalized = EllipticCurveKeyImport.Import(input);
            string signature = EllipticCurveCryptography.Sign("ECDSA-P256", normalized, "message");
            Assert.True(EllipticCurveCryptography.Verify("ECDSA-P256", key.ExportSubjectPublicKeyInfoPem(), "message", signature));
            Assert.Contains("BEGIN PRIVATE KEY", normalized);
        }
    }

    [Fact]
    public void ImportsSm2Sec1PrivateKey()
    {
        var keys = KeyGenerator.Generate("SM2");
        var info = Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo.GetInstance(Der(keys.PrivateKey));
        byte[] sec1 = info.ParsePrivateKey().GetDerEncoded();
        foreach (byte[] input in new[] { sec1, Encoding.UTF8.GetBytes(PemEncoding.WriteString("EC PRIVATE KEY", sec1)) })
        {
            string normalized = EllipticCurveKeyImport.Import(input);
            string signature = EllipticCurveCryptography.Sign("SM2", normalized, "message");
            Assert.True(EllipticCurveCryptography.Verify("SM2", keys.PublicKey, "message", signature));
        }
    }

    [Fact]
    public void ReadsPemFilesWithUtf8BomAndCrLf()
    {
        var keys = KeyGenerator.Generate("SM2");
        foreach (string pem in new[] { keys.PublicKey, keys.PrivateKey })
        {
            byte[] data = Encoding.UTF8.GetBytes("\uFEFF\r\n" + pem.Replace("\n", "\r\n", StringComparison.Ordinal));
            Assert.Equal(pem, EllipticCurveKeyImport.Import(data));
        }
    }

    [Fact]
    public void ImportedUnrelatedPrivateKeysAreRejectedByEllipticAlgorithms()
    {
        var keys = KeyGenerator.Generate("RSA-2048");
        string privateKey = EllipticCurveKeyImport.Import(Der(keys.PrivateKey));
        string publicKey = EllipticCurveKeyImport.Import(Der(keys.PublicKey));
        Assert.Throws<ArgumentException>(() => EllipticCurveCryptography.Sign("ECDSA-P256", privateKey, "message"));
        Assert.Throws<ArgumentException>(() => EllipticCurveCryptography.Encrypt("ECDH-P256", publicKey, "message"));
    }

    [Theory]
    [MemberData(nameof(CoordinateAlgorithms))]
    public void BuildsVerifyingPublicKeyFromCoordinates(string algorithm)
    {
        var keys = KeyGenerator.Generate(algorithm);
        var publicKey = (ECPublicKeyParameters)KeyGenerator.ReadKey(keys.PublicKey, false);
        var point = publicKey.Q.Normalize();
        string pem = EllipticCurveKeyImport.FromCoordinates(algorithm,
            "0x " + point.AffineXCoord.ToBigInteger().ToString(16), point.AffineYCoord.ToBigInteger().ToString(16));
        string signature = EllipticCurveCryptography.Sign(algorithm, keys.PrivateKey, "message");
        Assert.True(EllipticCurveCryptography.Verify(algorithm, pem, "message", signature));
    }

    [Fact]
    public void AllowsCoordinatesWithoutLeadingZeroPadding()
    {
        var curve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-256");
        var point = curve.G.Normalize();
        string pem = EllipticCurveKeyImport.FromCoordinates("ECDSA-P256", point.AffineXCoord.ToBigInteger().ToString(16), point.AffineYCoord.ToBigInteger().ToString(16));
        var key = (ECPublicKeyParameters)KeyGenerator.ReadKey(pem, false);
        Assert.Equal(point, key.Q);
    }

    [Theory]
    [InlineData("ECDSA-P256", "0", "0")]
    [InlineData("SM2", "1", "1")]
    [InlineData("ECDSA-P256", "not hex", "0")]
    [InlineData("ECDSA-P256", "", "0")]
    [InlineData("Ed25519", "1", "1")]
    public void RejectsInvalidCoordinates(string algorithm, string x, string y) =>
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.FromCoordinates(algorithm, x, y));

    [Fact]
    public void RejectsOversizedOrOutOfFieldCoordinates()
    {
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.FromCoordinates("ECDSA-P256", new string('f', 65), "1"));
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.FromCoordinates("ECDSA-P256", new string('f', 64), "1"));
    }

    [Fact]
    public void RejectsUnrecognizedFilesAndCsr()
    {
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.Import([]));
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.Import(Encoding.UTF8.GetBytes("not a key")));
        var csr = CertificateGenerator.Generate("SM2", "CN=test", "", 1, true);
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.Import(Encoding.UTF8.GetBytes(csr.Document)));
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.Import(Der(csr.Document)));
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.Import([0x30, 0]));
        Assert.Throws<ArgumentException>(() => EllipticCurveKeyImport.Import(Encoding.UTF8.GetBytes(PemEncoding.WriteString("PUBLIC KEY", [0x30, 0]))));
    }

    private static byte[] Der(string pem) => Convert.FromBase64String(pem[PemEncoding.Find(pem).Base64Data]);
}
