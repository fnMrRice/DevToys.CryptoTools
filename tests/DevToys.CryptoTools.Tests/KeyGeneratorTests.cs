using System.Security.Cryptography;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class KeyGeneratorTests
{
    public static IEnumerable<object[]> Algorithms => KeyGenerator.Algorithms.Select(a => new object[] { a });

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void GeneratesUsableKeys(string algorithm)
    {
        var key = KeyGenerator.Generate(algorithm);
        if (key.SymmetricKey.Length > 0)
        {
            Assert.Equal(int.Parse(algorithm.Split('-')[1]) / 8, Convert.FromBase64String(key.SymmetricKey).Length);
            Assert.NotEqual(key.SymmetricKey, KeyGenerator.Generate(algorithm).SymmetricKey);
            return;
        }
        Assert.Contains("BEGIN PUBLIC KEY", key.PublicKey);
        Assert.Contains("BEGIN PRIVATE KEY", key.PrivateKey);
        if (algorithm.StartsWith("RSA-", StringComparison.Ordinal))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(key.PrivateKey);
            Assert.Equal(int.Parse(algorithm[4..]), rsa.KeySize);
            Assert.Equal(key.PublicKey, rsa.ExportSubjectPublicKeyInfoPem());
        }
        else
        {
            Assert.True(KeyGenerator.ReadKey(key.PrivateKey, true).IsPrivate);
            Assert.False(KeyGenerator.ReadKey(key.PublicKey, false).IsPrivate);
        }
    }

    [Fact]
    public void RejectsUnknownAlgorithms() => Assert.Throws<ArgumentException>(() => KeyGenerator.Generate("unknown"));
}
