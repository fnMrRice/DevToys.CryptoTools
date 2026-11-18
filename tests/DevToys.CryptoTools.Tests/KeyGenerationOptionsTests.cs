using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class KeyGenerationOptionsTests
{
    public static IEnumerable<object[]> SupportedOptions
    {
        get
        {
            foreach (int size in KeyGenerationOptions.RsaKeySizes)
                yield return ["RSA", size, "unused", "RSA-" + size];
            foreach (string family in new[] { "ECDSA", "ECDH" })
                foreach (string curve in KeyGenerationOptions.Curves)
                    yield return [family, 0, curve, family + "-" + curve];
            foreach (string family in new[] { "Ed25519", "Ed448", "X25519", "X448", "SM2" })
                yield return [family, 0, "unused", family];
        }
    }

    [Theory]
    [MemberData(nameof(SupportedOptions))]
    public void EveryConfigurationResolvesToASupportedKeyVariant(string family, int size, string curve, string expected)
    {
        string algorithm = KeyGenerationOptions.Resolve(family, size, curve);
        Assert.Equal(expected, algorithm);
        Assert.Contains(algorithm, KeyGenerator.AsymmetricAlgorithms);
    }

    [Fact]
    public void OptionsCoverAllPreviouslySupportedAsymmetricVariants()
    {
        string[] resolved = SupportedOptions.Select(values => KeyGenerationOptions.Resolve((string)values[0], (int)values[1], (string)values[2])).ToArray();
        Assert.Equal(KeyGenerator.AsymmetricAlgorithms.Order(StringComparer.Ordinal), resolved.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    [InlineData("X25519")]
    [InlineData("X448")]
    [InlineData("SM2")]
    public void FixedFamiliesIgnoreUnrelatedKeySizesAndCurves(string family)
    {
        Assert.Equal(family, KeyGenerationOptions.Resolve(family, int.MinValue, "unsupported"));
        Assert.Equal(family, KeyGenerationOptions.Resolve(family, int.MaxValue, null!));
    }

    [Fact]
    public void RsaIgnoresTheCurveAndEcFamiliesIgnoreTheRsaSize()
    {
        Assert.Equal("RSA-3072", KeyGenerationOptions.Resolve("RSA", 3072, null!));
        Assert.Equal("ECDSA-secp256k1", KeyGenerationOptions.Resolve("ECDSA", -1, "secp256k1"));
        Assert.Equal("ECDH-P521", KeyGenerationOptions.Resolve("ECDH", 123, "P521"));
    }

    [Theory]
    [InlineData("unknown", 2048, "P256")]
    [InlineData("", 2048, "P256")]
    [InlineData("RSA-2048", 2048, "P256")]
    [InlineData("RSA", 1024, "P256")]
    [InlineData("RSA", 0, "P256")]
    [InlineData("RSA", 8192, "P256")]
    [InlineData("ECDSA", 2048, "unknown")]
    [InlineData("ECDH", 2048, "")]
    [InlineData("ECDH", 2048, "P25519")]
    [InlineData("ecdsa", 2048, "P256")]
    public void UnknownRelevantOptionsAreRejected(string family, int size, string curve) =>
        Assert.Throws<ArgumentException>(() => KeyGenerationOptions.Resolve(family, size, curve));
}
