using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevToys.CryptoTools.Tests;

public class PublicKeyInputTests
{
    public static IEnumerable<object[]> Algorithms => EllipticCurveCryptography.SigningAlgorithms
        .Concat(EllipticCurveCryptography.EncryptionAlgorithms).Distinct().Select(a => new object[] { a });

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void EncodedSpkiAndRawPublicKeysMatchGeneratedKeys(string algorithm)
    {
        string keyAlgorithm = algorithm.StartsWith("SM2-", StringComparison.Ordinal) ? "SM2" : algorithm;
        var generated = KeyGenerator.Generate(keyAlgorithm);
        byte[] der = PemBytes(generated.PublicKey);
        Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, generated.PublicKey, PublicKeyEncoding.Pem));
        Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToBase64String(der), PublicKeyEncoding.Base64));
        Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToHexString(der), PublicKeyEncoding.Hex));
        var key = KeyGenerator.ReadKey(generated.PublicKey, false);
        byte[] raw = key switch
        {
            ECPublicKeyParameters ec => ec.Q.GetEncoded(false),
            Ed25519PublicKeyParameters ed => ed.GetEncoded(),
            Ed448PublicKeyParameters ed => ed.GetEncoded(),
            X25519PublicKeyParameters x => x.GetEncoded(),
            X448PublicKeyParameters x => x.GetEncoded(),
            _ => throw new InvalidOperationException()
        };
        Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToBase64String(raw), PublicKeyEncoding.Base64));
        Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, "0x" + Convert.ToHexString(raw), PublicKeyEncoding.Hex));
        if (key is ECPublicKeyParameters prime)
        {
            Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToHexString(raw[1..]), PublicKeyEncoding.Hex));
            Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToHexString(prime.Q.GetEncoded(true)), PublicKeyEncoding.Hex));
            string xHex = prime.Q.Normalize().AffineXCoord.ToBigInteger().ToString(16);
            string yHex = prime.Q.Normalize().AffineYCoord.ToBigInteger().ToString(16);
            Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.FromCoordinates(algorithm, xHex, yHex, PublicKeyEncoding.Hex));
            byte[] x = prime.Q.Normalize().AffineXCoord.GetEncoded();
            byte[] y = prime.Q.Normalize().AffineYCoord.GetEncoded();
            Assert.Equal(generated.PublicKey, EllipticCurvePublicKeyInput.FromCoordinates(algorithm, Convert.ToBase64String(x), Convert.ToBase64String(y), PublicKeyEncoding.Base64));
        }
    }

    [Theory]
    [InlineData("SM2")]
    [InlineData("ECDSA-P256")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    public void CertificatePemAndEncodedDerExtractTheSamePublicKey(string algorithm)
    {
        var certificate = CertificateGenerator.Generate(algorithm, "CN=encoded.example", "", 30, false);
        string expected = EllipticCurveKeyImport.Import(Encoding.UTF8.GetBytes(certificate.Document));
        byte[] der = PemBytes(certificate.Document);
        Assert.Equal(expected, EllipticCurvePublicKeyInput.Decode(algorithm, certificate.Document, PublicKeyEncoding.Pem));
        Assert.Equal(expected, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToBase64String(der), PublicKeyEncoding.Base64));
        Assert.Equal(expected, EllipticCurvePublicKeyInput.Decode(algorithm, Convert.ToHexString(der), PublicKeyEncoding.Hex));
    }

    [Fact]
    public void RejectsWrongCurvePrivateMaterialAndInvalidPoints()
    {
        var key = KeyGenerator.Generate("ECDSA-P256");
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.Decode("SM2", key.PublicKey, PublicKeyEncoding.Pem));
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.Decode("ECDSA-P384", Convert.ToBase64String(PemBytes(key.PublicKey)), PublicKeyEncoding.Base64));
        foreach (var encoding in Enum.GetValues<PublicKeyEncoding>())
        {
            string input = encoding switch
            {
                PublicKeyEncoding.Pem => key.PrivateKey,
                PublicKeyEncoding.Base64 => Convert.ToBase64String(PemBytes(key.PrivateKey)),
                _ => Convert.ToHexString(PemBytes(key.PrivateKey))
            };
            Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.Decode("ECDSA-P256", input, encoding));
        }
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.Decode("ECDSA-P256", "04" + new string('0', 128), PublicKeyEncoding.Hex));
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.Decode("Ed25519", "00", PublicKeyEncoding.Hex));
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.FromCoordinates("SM2", "AA==", "AA==", PublicKeyEncoding.Base64));
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.FromCoordinates("Ed25519", "00", "00", PublicKeyEncoding.Hex));
        Assert.Throws<ArgumentException>(() => EllipticCurvePublicKeyInput.FromCoordinates("SM2", "AA==", "AA==", (PublicKeyEncoding)99));
    }

    private static byte[] PemBytes(string pem) => Convert.FromBase64String(pem[PemEncoding.Find(pem).Base64Data]);
}
