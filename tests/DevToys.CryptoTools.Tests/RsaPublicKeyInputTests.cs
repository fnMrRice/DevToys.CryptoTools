using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class RsaPublicKeyInputTests
{
    private static readonly KeyMaterial Keys = KeyGenerator.Generate("RSA-2048");

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void PublicKeyAndCertificateEncodingsEncryptAndVerify(int format)
    {
        var encoding = (PublicKeyEncoding)format;
        var certificate = CertificateGenerator.Generate(new CertificateOptions { Subject = "CN=rsa.example", PrivateKeyPem = Keys.PrivateKey });
        foreach (string pem in new[] { Keys.PublicKey, certificate.Document })
        {
            string publicKey = RsaPublicKeyInput.Decode(Encode(pem, encoding), encoding);
            Assert.Equal(Keys.PublicKey, publicKey);
            string encrypted = RsaCryptography.Encrypt(publicKey, "hello 🔑", "OAEP-SHA256");
            Assert.Equal("hello 🔑", RsaCryptography.Decrypt(Keys.PrivateKey, encrypted, "OAEP-SHA256"));
            string signature = RsaCryptography.Sign(Keys.PrivateKey, "message", "SHA256", "PSS");
            Assert.True(RsaCryptography.Verify(publicKey, "message", signature, "SHA256", "PSS"));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Pkcs1PublicKeyEncodingsNormalizeToSpki(int format)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Keys.PrivateKey);
        var encoding = (PublicKeyEncoding)format;
        Assert.Equal(Keys.PublicKey, RsaPublicKeyInput.Decode(Encode(rsa.ExportRSAPublicKeyPem(), encoding), encoding));
    }

    [Fact]
    public void GenericFileImporterAcceptsPkcs1PrivateDer()
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Keys.PrivateKey);
        Assert.Equal(Keys.PrivateKey, EllipticCurveKeyImport.Import(rsa.ExportRSAPrivateKey()));
        Assert.Equal(Keys.PrivateKey, EllipticCurveKeyImport.Import(Encoding.UTF8.GetBytes(rsa.ExportRSAPrivateKeyPem())));
        Assert.Equal(Keys.PublicKey, EllipticCurveKeyImport.Import(rsa.ExportRSAPublicKey()));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void ModulusAndExponentSupportBase64AndHex(int format)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Keys.PrivateKey);
        var parameters = rsa.ExportParameters(false);
        var encoding = (PublicKeyEncoding)format;
        string n = encoding == PublicKeyEncoding.Base64 ? Convert.ToBase64String(parameters.Modulus!) : "0x" + Convert.ToHexString(parameters.Modulus!);
        string e = encoding == PublicKeyEncoding.Base64 ? Convert.ToBase64String(parameters.Exponent!) : "0x1 00 01";
        Assert.Equal(Keys.PublicKey, RsaPublicKeyInput.FromParameters(n, e, encoding));
    }

    [Fact]
    public void RejectsPrivateKeysOtherKeyTypesAndInvalidParameterValues()
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Keys.PrivateKey);
        var ec = KeyGenerator.Generate("ECDSA-P256");
        foreach (var encoding in Enum.GetValues<PublicKeyEncoding>())
        {
            Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.Decode(Encode(Keys.PrivateKey, encoding), encoding));
            Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.Decode(Encode(rsa.ExportRSAPrivateKeyPem(), encoding), encoding));
            Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.Decode(Encode(ec.PublicKey, encoding), encoding));
        }
        string n = Convert.ToHexString(rsa.ExportParameters(false).Modulus!);
        foreach (string exponent in new[] { "", "00", "01", "02", n })
            Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.FromParameters(n, exponent, PublicKeyEncoding.Hex));
        foreach (string modulus in new[] { "", "00", "11", new string('F', 126) + "FE" })
            Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.FromParameters(modulus, "010001", PublicKeyEncoding.Hex));
        Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.FromParameters(n, "010001", PublicKeyEncoding.Pem));
        Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.Decode(Keys.PublicKey, (PublicKeyEncoding)99));
        Assert.Throws<ArgumentException>(() => RsaPublicKeyInput.Decode("3000", PublicKeyEncoding.Hex));
    }

    private static string Encode(string pem, PublicKeyEncoding encoding)
    {
        byte[] der = Convert.FromBase64String(pem[PemEncoding.Find(pem).Base64Data]);
        return encoding switch
        {
            PublicKeyEncoding.Pem => pem,
            PublicKeyEncoding.Base64 => Convert.ToBase64String(der),
            _ => Convert.ToHexString(der)
        };
    }
}
