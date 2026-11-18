using System.Security.Cryptography;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class RsaCryptographyTests
{
    private static readonly KeyMaterial Keys = KeyGenerator.Generate("RSA-2048");

    [Theory]
    [InlineData("OAEP-SHA256", 190)]
    [InlineData("OAEP-SHA384", 158)]
    [InlineData("OAEP-SHA512", 126)]
    [InlineData("PKCS1", 245)]
    public void EncryptsToPaddingLimitAndRejectsOversizedMessages(string padding, int maximumBytes)
    {
        string message = new('a', maximumBytes);
        string encrypted = RsaCryptography.Encrypt(Keys.PublicKey, message, padding);
        Assert.Equal(message, RsaCryptography.Decrypt(Keys.PrivateKey, encrypted, padding));
        Assert.Throws<ArgumentException>(() => RsaCryptography.Encrypt(Keys.PublicKey, message + "a", padding));
        Assert.Throws<CryptographicException>(() => RsaCryptography.Decrypt(Keys.PublicKey, encrypted, padding));
    }

    [Theory]
    [InlineData("SHA256", "PSS")]
    [InlineData("SHA384", "PSS")]
    [InlineData("SHA512", "PSS")]
    [InlineData("SHA256", "PKCS1")]
    [InlineData("SHA384", "PKCS1")]
    [InlineData("SHA512", "PKCS1")]
    public void SignaturesVerifyAndDetectModifiedMessages(string hash, string padding)
    {
        string signature = RsaCryptography.Sign(Keys.PrivateKey, "你好 🔑", hash, padding);
        Assert.True(RsaCryptography.Verify(Keys.PublicKey, "你好 🔑", signature, hash, padding));
        Assert.False(RsaCryptography.Verify(Keys.PublicKey, "modified", signature, hash, padding));
    }
}
