using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class SymmetricCipherTests
{
    [Theory]
    [InlineData(0, "AAEC/w==")]
    [InlineData(1, "00 01 02 FF")]
    public void DecodesBinaryFormats(int encoding, string input) =>
        Assert.Equal(new byte[] { 0, 1, 2, 255 }, BinaryText.Decode(input, (BinaryEncoding)encoding));

    [Fact]
    public void TextEncodingPreservesUnicodeAndWhitespace()
    {
        const string text = "  你好 🔑\n";
        Assert.Equal(text, BinaryText.Encode(BinaryText.Decode(text, BinaryEncoding.Text), BinaryEncoding.Text));
        Assert.Throws<ArgumentException>(() => BinaryText.Encode([255], BinaryEncoding.Text));
    }

    [Theory]
    [InlineData("AES-CBC", PaddingMode.PKCS7)]
    [InlineData("AES-CBC", PaddingMode.None)]
    [InlineData("SM4-CBC", PaddingMode.PKCS7)]
    [InlineData("SM4-CBC", PaddingMode.None)]
    [InlineData("AES-GCM", PaddingMode.None)]
    [InlineData("SM4-GCM", PaddingMode.None)]
    [InlineData("ChaCha20-Poly1305", PaddingMode.None)]
    public void RawCiphertextRoundTripsBinaryDataWithExplicitIv(string algorithm, PaddingMode padding)
    {
        byte[] key = RandomNumberGenerator.GetBytes(algorithm == "ChaCha20-Poly1305" ? 32 : 16);
        byte[] iv = RandomNumberGenerator.GetBytes(SymmetricCipher.IvLength(algorithm));
        byte[] data = Enumerable.Range(0, 256).Select(n => (byte)n).ToArray();
        byte[] encrypted = SymmetricCipher.Transform(true, algorithm, key, iv, data, padding);
        Assert.Equal(data, SymmetricCipher.Transform(false, algorithm, key, iv, encrypted, padding));
    }

    [Fact]
    public void AesCbcMatchesNistSp80038AVector()
    {
        byte[] key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a");
        byte[] ciphertext = SymmetricCipher.Transform(true, "AES-CBC", key, iv, plaintext);
        Assert.Equal("7649ABAC8119B246CEE98E9B12E9197D", Convert.ToHexString(ciphertext));
    }

    [Fact]
    public void AesGcmMatchesNistEmptyMessageVector()
    {
        byte[] ciphertext = SymmetricCipher.Transform(true, "AES-GCM", new byte[16], new byte[12], []);
        Assert.Equal("58E2FCCEFA7E3061367F1D57A4E7455A", Convert.ToHexString(ciphertext));
    }

    [Theory]
    [InlineData("AES-GCM")]
    [InlineData("SM4-GCM")]
    [InlineData("ChaCha20-Poly1305")]
    public void RawAuthenticatedModesRejectTampering(string algorithm)
    {
        byte[] key = new byte[algorithm == "ChaCha20-Poly1305" ? 32 : 16];
        byte[] iv = new byte[12];
        byte[] encrypted = SymmetricCipher.Transform(true, algorithm, key, iv, Encoding.UTF8.GetBytes("message"));
        encrypted[^1] ^= 1;
        Assert.ThrowsAny<Exception>(() => SymmetricCipher.Transform(false, algorithm, key, iv, encrypted));
    }

    [Fact]
    public void RejectsInvalidSettingsBeforeEncryption()
    {
        Assert.Throws<ArgumentException>(() => SymmetricCipher.Transform(true, "AES-GCM", new byte[16], new byte[16], []));
        Assert.Throws<ArgumentException>(() => SymmetricCipher.Transform(true, "SM4-CBC", new byte[32], new byte[16], []));
        Assert.Throws<ArgumentException>(() => SymmetricCipher.Transform(true, "AES-GCM", new byte[16], new byte[12], [], PaddingMode.PKCS7));
        Assert.Throws<ArgumentException>(() => SymmetricCipher.Transform(true, "AES-CBC", new byte[16], new byte[16], [1]));
    }
}
