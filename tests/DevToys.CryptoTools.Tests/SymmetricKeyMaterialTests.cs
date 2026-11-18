using System.Text;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class SymmetricKeyMaterialTests
{
    [Fact]
    public void ShortKeyIsZeroPaddedOnTheRightWithoutChangingInput()
    {
        byte[] input = [0x12, 0x34, 0x56];
        byte[] normalized = SymmetricKeyMaterial.Normalize("AES", input, 16);
        Assert.Equal("12345600000000000000000000000000", Convert.ToHexString(normalized));
        Assert.Equal(new byte[] { 0x12, 0x34, 0x56 }, input);
    }

    [Fact]
    public void LongKeyDiscardsTheTailWithoutChangingInput()
    {
        byte[] input = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        byte[] normalized = SymmetricKeyMaterial.Normalize("AES", input, 16);
        Assert.Equal("0102030405060708090A0B0C0D0E0F10", Convert.ToHexString(normalized));
        Assert.Equal(32, input.Length);
        Assert.Equal(32, input[^1]);
    }

    [Fact]
    public void ExactKeyIsCopiedAndEmptyKeyIsZeroFilled()
    {
        byte[] input = Enumerable.Repeat((byte)0xaa, 16).ToArray();
        byte[] normalized = SymmetricKeyMaterial.Normalize("AES", input, 16);
        Assert.Equal(input, normalized);
        Assert.NotSame(input, normalized);
        Assert.Equal(new byte[16], SymmetricKeyMaterial.Normalize("SM4", [], 16));
    }

    [Fact]
    public void TextKeysAreNormalizedAfterUtf8DecodingByByteCount()
    {
        byte[] input = Encoding.UTF8.GetBytes("🔑");
        Assert.Equal("F09F9491000000000000000000000000", Convert.ToHexString(SymmetricKeyMaterial.Normalize("AES", input, 16)));
        Assert.Equal(4, input.Length);
    }

    [Theory]
    [InlineData("AES", 20)]
    [InlineData("SM4", 32)]
    [InlineData("DES", 16)]
    [InlineData("Blowfish", 57)]
    [InlineData("RC2", 129)]
    public void InvalidSelectedLengthIsRejected(string algorithm, int bytes) =>
        Assert.Throws<ArgumentException>(() => SymmetricKeyMaterial.Normalize(algorithm, [1, 2, 3], bytes));
}
