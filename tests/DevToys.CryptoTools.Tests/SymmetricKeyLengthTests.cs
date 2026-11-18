using System.Security.Cryptography;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class SymmetricKeyLengthTests
{
    public static IEnumerable<object[]> Algorithms => SymmetricAlgorithmCatalog.Algorithms.Select(algorithm => new object[] { algorithm });

    public static IEnumerable<object[]> ExecutionLengths => SymmetricAlgorithmCatalog.Algorithms.SelectMany(algorithm =>
    {
        int[] lengths = SymmetricAlgorithmCatalog.KeyLengths(algorithm);
        IEnumerable<int> cases = algorithm is "AES" or "TripleDES" or "Salsa20"
            ? lengths : new[] { lengths[0], lengths[^1] }.Distinct();
        return cases.Select(length => new object[] { algorithm, length });
    });

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void AvailableLengthsAreSortedSupportedAndIncludeTheDefault(string algorithm)
    {
        int[] lengths = SymmetricAlgorithmCatalog.KeyLengths(algorithm);
        Assert.NotEmpty(lengths);
        Assert.Equal(lengths.Distinct().Order(), lengths);
        Assert.Contains(SymmetricAlgorithmCatalog.DefaultKeyLength(algorithm), lengths);
        foreach (string mode in SymmetricAlgorithmCatalog.Modes(algorithm))
        {
            foreach (int length in lengths)
                Assert.True(SymmetricAlgorithmCatalog.IsKeyLengthValid(algorithm + "-" + mode, length));
            Assert.False(SymmetricAlgorithmCatalog.IsKeyLengthValid(algorithm + "-" + mode, lengths[0] - 1));
            Assert.False(SymmetricAlgorithmCatalog.IsKeyLengthValid(algorithm + "-" + mode, lengths[^1] + 1));
        }
    }

    [Theory]
    [MemberData(nameof(ExecutionLengths))]
    public void OfferedBoundaryAndDiscreteLengthsWorkWithTheCipher(string algorithm, int length)
    {
        string mode = SymmetricAlgorithmCatalog.Modes(algorithm)[0];
        string full = algorithm + "-" + mode;
        byte[] key = RandomNumberGenerator.GetBytes(length);
        byte[] iv = RandomNumberGenerator.GetBytes(SymmetricAlgorithmCatalog.IvLength(full));
        byte[] plaintext = [0, 1, 2, 3, 255, 254, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];
        var padding = mode == "CBC" ? PaddingMode.PKCS7 : PaddingMode.None;
        byte[] encrypted = SymmetricCipher.Transform(true, full, key, iv, plaintext, padding);
        Assert.Equal(plaintext, SymmetricCipher.Transform(false, full, key, iv, encrypted, padding));
    }

    [Theory]
    [InlineData("AES", 17)]
    [InlineData("Camellia", 20)]
    [InlineData("TripleDES", 20)]
    [InlineData("Salsa20", 24)]
    public void DiscreteAlgorithmsDoNotOfferIntermediateLengths(string algorithm, int length)
    {
        Assert.DoesNotContain(length, SymmetricAlgorithmCatalog.KeyLengths(algorithm));
        Assert.False(SymmetricAlgorithmCatalog.IsKeyLengthValid(algorithm + "-" + SymmetricAlgorithmCatalog.Modes(algorithm)[0], length));
    }

    [Fact]
    public void UnknownAlgorithmDoesNotReturnAKeyLength() =>
        Assert.Throws<ArgumentException>(() => SymmetricAlgorithmCatalog.KeyLengths("unknown"));
}
