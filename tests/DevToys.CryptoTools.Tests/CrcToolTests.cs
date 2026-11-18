using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class CrcToolTests
{
    [Theory]
    [InlineData(2, "123456789")]
    [InlineData(1, "31 32 33 34 35 36 37 38 39")]
    [InlineData(0, "MTIzNDU2Nzg5")]
    public async Task DefaultCrc32AcceptsAllInputEncodings(int encoding, string input)
    {
        var tool = new CrcTool();
        Assert.True(tool.View.IsScrollable);
        Select(tool, "crc-input-encoding", (BinaryEncoding)encoding);
        Find<IUIMultiLineTextInput>(tool, "crc-input").Text(input);
        await Calculate(tool);
        Assert.Equal("CBF43926", Result(tool));
        Assert.Equal("CBF43926", Find<IUISingleLineTextInput>(tool, "crc-check").Text);
    }

    [Fact]
    public async Task EditingPolynomialAndParametersAutomaticallySwitchesToCustom()
    {
        var tool = new CrcTool();
        Find<IUINumberInput>(tool, "crc-width").Value(16);
        Find<IUISingleLineTextInput>(tool, "crc-polynomial").Text("0x1021");
        Find<IUISingleLineTextInput>(tool, "crc-initial").Text("FFFF");
        Find<IUISingleLineTextInput>(tool, "crc-xor-out").Text("0000");
        Find<IUISwitch>(tool, "crc-ref-in").Off();
        Find<IUISwitch>(tool, "crc-ref-out").Off();
        Assert.Equal("custom", Find<IUISelectDropDownList>(tool, "crc-preset").SelectedItem!.Value);
        Assert.Empty(Find<IUISingleLineTextInput>(tool, "crc-check").Text);
        await Calculate(tool);
        Assert.Equal("29B1", Result(tool));
        Select(tool, "crc-preset", "CRC-16/MODBUS");
        await Calculate(tool);
        Assert.Equal("4B37", Result(tool));
    }

    [Fact]
    public async Task InputEditsAutomaticallyUpdateHexResult()
    {
        var tool = new CrcTool();
        await Calculate(tool);
        Assert.Equal("CBF43926", Result(tool));
        Find<IUIMultiLineTextInput>(tool, "crc-input").Text("changed");
        await Calculate(tool);
        Assert.NotEmpty(Result(tool));
        Assert.NotEqual("CBF43926", Result(tool));
    }

    [Fact]
    public async Task Width64AndSubByteOutputAreNotTruncatedOrSignExtended()
    {
        var tool = new CrcTool();
        Select(tool, "crc-preset", "CRC-64/XZ");
        await Calculate(tool);
        Assert.Equal("995DC9BBDF1939FA", Result(tool));
        Select(tool, "crc-preset", "CRC-3/GSM");
        await Calculate(tool);
        Assert.Equal("4", Result(tool));
    }

    [Fact]
    public async Task InvalidCustomPolynomialClearsThePreviousResult()
    {
        var tool = new CrcTool();
        await Calculate(tool);
        Find<IUISingleLineTextInput>(tool, "crc-polynomial").Text("100000000");
        await Calculate(tool);
        Assert.Empty(Result(tool));
        Find<IUISingleLineTextInput>(tool, "crc-polynomial").Text("0");
        await Calculate(tool);
        Assert.Empty(Result(tool));
    }

    private static T Find<T>(CrcTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    [Theory]
    [InlineData("cbf43926", "CrcMatches")]
    [InlineData("0xCBF43926", "CrcMatches")]
    [InlineData("00000000", "CrcDoesNotMatch")]
    [InlineData("100000000", "InvalidCrcHex")]
    public async Task ExpectedHexChecksumIsAutomaticallyComparedWhenInputChanges(string expected, string message)
    {
        var tool = new CrcTool();
        Find<IUISingleLineTextInput>(tool, "crc-expected").Text(expected);
        await Calculate(tool);
        var verification = Find<IUIInfoBar>(tool, "crc-verification");
        Assert.True(verification.IsVisible);
        Assert.Equal(DevToys.CryptoTools.Localization.Text.L(message), verification.Description);
        Find<IUIMultiLineTextInput>(tool, "crc-input").Text("changed");
        await Calculate(tool);
        Assert.True(verification.IsVisible);
        Assert.NotEqual("CBF43926", Result(tool));
    }

    private static string Result(CrcTool tool) => Find<IUISingleLineTextInput>(tool, "crc-output").Text;
    private static void Select(CrcTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Calculate(CrcTool tool) => await tool.CalculationTask;
}
