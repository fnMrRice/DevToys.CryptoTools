using System.Security.Cryptography;
using System.Text.Json.Nodes;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class SymmetricCryptographyTests
{
    public static IEnumerable<object[]> Cases => SymmetricCryptography.Algorithms.SelectMany(a =>
        (a.StartsWith("AES-", StringComparison.Ordinal) ? new[] { 16, 24, 32 } : new[] { a == "ChaCha20-Poly1305" ? 32 : 16 })
        .SelectMany(n => new[] { "", "你好 🔑", new string('a', 1024) }.Select(message => new object[] { a, n, message })));

    [Theory]
    [MemberData(nameof(Cases))]
    public void RoundTripsAllKeyLengthsAndTextSizes(string algorithm, int length, string message)
    {
        string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(length));
        string encrypted = SymmetricCryptography.Encrypt(algorithm, key, message);
        Assert.Equal(message, SymmetricCryptography.Decrypt(algorithm, key, encrypted));
        Assert.NotEqual(encrypted, SymmetricCryptography.Encrypt(algorithm, key, message));
    }

    [Theory]
    [InlineData("AES-GCM", 32)]
    [InlineData("ChaCha20-Poly1305", 32)]
    [InlineData("SM4-GCM", 16)]
    public void AuthenticatedModesRejectTamperingAndWrongKeys(string algorithm, int length)
    {
        string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(length));
        string encrypted = SymmetricCryptography.Encrypt(algorithm, key, "message");
        string wrongKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(length));
        Assert.ThrowsAny<Exception>(() => SymmetricCryptography.Decrypt(algorithm, wrongKey, encrypted));
        foreach (string field in new[] { "nonce", "tag", "ciphertext" })
        {
            var json = JsonNode.Parse(encrypted)!;
            byte[] bytes = Convert.FromBase64String(json[field]!.GetValue<string>());
            bytes[0] ^= 1;
            json[field] = Convert.ToBase64String(bytes);
            Assert.ThrowsAny<Exception>(() => SymmetricCryptography.Decrypt(algorithm, key, json.ToJsonString()));
        }
    }

    [Theory]
    [InlineData("AES-GCM")]
    [InlineData("AES-CBC")]
    [InlineData("ChaCha20-Poly1305")]
    [InlineData("SM4-GCM")]
    [InlineData("SM4-CBC")]
    public void RejectsBadKeyLengthsAndEnvelopes(string algorithm)
    {
        Assert.Throws<ArgumentException>(() => SymmetricCryptography.Encrypt(algorithm, Convert.ToBase64String(new byte[15]), "text"));
        int length = algorithm.StartsWith("SM4", StringComparison.Ordinal) ? 16 : 32;
        string key = Convert.ToBase64String(new byte[length]);
        Assert.Throws<ArgumentException>(() => SymmetricCryptography.Decrypt(algorithm, key, "{}"));
        Assert.Throws<ArgumentException>(() => SymmetricCryptography.Decrypt(algorithm, key, "null"));
    }
}
