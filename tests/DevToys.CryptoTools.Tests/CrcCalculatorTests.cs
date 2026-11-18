using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class CrcCalculatorTests
{
    public static IEnumerable<object[]> PresetNames =>
        CrcCalculator.Presets.Select(preset => new object[] { preset.Name });

    [Theory]
    [MemberData(nameof(PresetNames))]
    public void PresetsMatchPublishedRevEngCheckValues(string name)
    {
        CrcPreset preset = Assert.Single(CrcCalculator.Presets, item => item.Name == name);
        Assert.Equal(preset.Check, CrcCalculator.Compute("123456789"u8, preset.Parameters));
    }

    [Fact]
    public void PresetsHaveUniqueNamesAndCoverCommonWidths()
    {
        Assert.Equal(CrcCalculator.Presets.Length, CrcCalculator.Presets.Select(preset => preset.Name).Distinct().Count());
        Assert.Contains(CrcCalculator.Presets, preset => preset.Name == "CRC-32/ISO-HDLC");
        foreach (int width in new[] { 3, 4, 5, 7, 8, 12, 15, 16, 24, 32, 64 })
            Assert.Contains(CrcCalculator.Presets, preset => preset.Parameters.Width == width);
    }

    [Theory]
    [InlineData(false, false, 0xB7UL)]
    [InlineData(true, false, 0xB7UL)]
    [InlineData(false, true, 0xEDUL)]
    [InlineData(true, true, 0xEDUL)]
    public void EmptyInputAppliesInitialOutputReflectionAndFinalXor(bool reflectInput, bool reflectOutput, ulong expected)
    {
        // 0x12 XOR 0xA5 = 0xB7; reflect8(0x12) XOR 0xA5 = 0xED.
        var parameters = new CrcParameters(8, 0x07, 0x12, reflectInput, reflectOutput, 0xA5);
        Assert.Equal(expected, CrcCalculator.Compute([], parameters));
    }

    [Theory]
    [InlineData(false, false, 0x3UL)]
    [InlineData(true, false, 0xCUL)]
    [InlineData(false, true, 0xCUL)]
    [InlineData(true, true, 0x3UL)]
    public void CustomFourBitPolynomialHonorsReflectionIndependently(bool reflectInput, bool reflectOutput, ulong expected)
    {
        // Polynomial division: (0x12 << 4) mod 0x13 = 3;
        // reflecting the input changes 0x12 to 0x48, whose remainder is C.
        var parameters = new CrcParameters(4, 0x3, 0, reflectInput, reflectOutput, 0);
        Assert.Equal(expected, CrcCalculator.Compute([0x12], parameters));
    }

    [Fact]
    public void CustomThreeBitPolynomialProcessesAllEightInputBits()
    {
        // (0x12 << 3) mod 0xB = 7.
        Assert.Equal(7UL, CrcCalculator.Compute([0x12], new(3, 0x3, 0, false, false, 0)));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void OneBitPolynomialComputesParity(bool reflectInput, bool reflectOutput)
    {
        Assert.Equal(1UL, CrcCalculator.Compute([0x80, 0x01, 0x7F], new(1, 1, 0, reflectInput, reflectOutput, 0)));
        Assert.Equal(0UL, CrcCalculator.Compute([0x80, 0x01, 0x7F], new(1, 1, 1, reflectInput, reflectOutput, 0)));
    }

    [Fact]
    public void FullWidthRegisterDiscardsOverflowAndHandlesHighestBit()
    {
        Assert.Equal(1UL, CrcCalculator.Compute([0x02], new(64, ulong.MaxValue, 0, false, false, 0)));
        Assert.Equal(0x80UL, CrcCalculator.Compute([0x00], new(64, 1, 0x8000000000000000, false, false, 0)));
        Assert.Equal(0x0100000000000000UL, CrcCalculator.Compute([0x00], new(64, 1, 0x8000000000000000, false, true, 0)));
    }

    [Fact]
    public void ManualPolynomialCanHaveAZeroConstantTerm()
    {
        // (0x01 << 4) mod 0x12 = 2.
        Assert.Equal(2UL, CrcCalculator.Compute([0x01], new(4, 2, 0, false, false, 0)));
    }

    [Theory]
    [InlineData("0", 1, 0UL)]
    [InlineData(" 0x 1 ", 1, 1UL)]
    [InlineData("0X 0a bC\r\n", 12, 0xABCUL)]
    [InlineData("00000000000000000001", 1, 1UL)]
    [InlineData("FFFFFFFFFFFFFFFF", 64, ulong.MaxValue)]
    public void ParseHexAcceptsWhitespacePrefixAndWidthBoundaries(string text, int width, ulong expected) =>
        Assert.Equal(expected, CrcCalculator.ParseHex(text, width));

    [Theory]
    [InlineData("", 8)]
    [InlineData(" \t\r\n", 8)]
    [InlineData("0x", 8)]
    [InlineData("-1", 8)]
    [InlineData("+1", 8)]
    [InlineData("1_0", 8)]
    [InlineData("0b10", 8)]
    [InlineData("gg", 8)]
    [InlineData("100", 8)]
    [InlineData("8", 3)]
    [InlineData("10000000000000000", 64)]
    public void ParseHexRejectsMalformedOrOutOfWidthValues(string text, int width) =>
        Assert.Throws<ArgumentException>(() => CrcCalculator.ParseHex(text, width));

    [Theory]
    [InlineData(0UL, 1, "0")]
    [InlineData(1UL, 3, "1")]
    [InlineData(1UL, 5, "01")]
    [InlineData(0xABCUL, 12, "ABC")]
    [InlineData(0x59EUL, 15, "059E")]
    [InlineData(0x376E6E7UL, 32, "0376E6E7")]
    [InlineData(1UL, 64, "0000000000000001")]
    [InlineData(ulong.MaxValue, 64, "FFFFFFFFFFFFFFFF")]
    public void FormatHexUsesFixedWidthUppercaseWithoutPrefix(ulong value, int width, string expected) =>
        Assert.Equal(expected, CrcCalculator.FormatHex(value, width));

    [Theory]
    [InlineData(0, 1UL, 0UL, 0UL)]
    [InlineData(-1, 1UL, 0UL, 0UL)]
    [InlineData(65, 1UL, 0UL, 0UL)]
    [InlineData(8, 0UL, 0UL, 0UL)]
    [InlineData(8, 0x107UL, 0UL, 0UL)]
    [InlineData(8, 7UL, 0x100UL, 0UL)]
    [InlineData(8, 7UL, 0UL, 0x100UL)]
    public void ComputeRejectsInvalidParameters(int width, ulong polynomial, ulong initial, ulong xorOut) =>
        Assert.Throws<ArgumentException>(() => CrcCalculator.Compute([], new(width, polynomial, initial, false, false, xorOut)));

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    public void HexHelpersRejectInvalidWidths(int width)
    {
        Assert.Throws<ArgumentException>(() => CrcCalculator.ParseHex("0", width));
        Assert.Throws<ArgumentException>(() => CrcCalculator.FormatHex(0, width));
    }

    [Fact]
    public void FormatHexRejectsValueOutsideWidth() =>
        Assert.Throws<ArgumentException>(() => CrcCalculator.FormatHex(0x10, 4));

    [Fact]
    public void NullArgumentsAreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => CrcCalculator.Compute([], null!));
        Assert.Throws<ArgumentNullException>(() => CrcCalculator.ParseHex(null!, 8));
    }
}
