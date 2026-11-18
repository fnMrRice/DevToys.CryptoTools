using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class SymmetricToolTests
{
    [Fact]
    public void UsesTwoConfigurationColumnsResizableEditorsAndHexDefaults()
    {
        var tool = new SymmetricTool();
        Assert.False(tool.View.IsScrollable);
        Assert.Equal(2, Find<IUIGrid>(tool, "sym-configuration").Columns!.Length);
        var editors = Find<IUISplitGrid>(tool, "sym-editors");
        Assert.Equal(UIOrientation.Vertical, editors.Orientation);
        Assert.Same(Find<IUIMultiLineTextInput>(tool, "sym-input"), editors.LeftOrTopCellContent);
        Assert.Same(Find<IUIMultiLineTextInput>(tool, "sym-output"), editors.RightOrBottomCellContent);
        Assert.Equal(BinaryEncoding.Hex, Find<IUISelectDropDownList>(tool, "sym-key-encoding").SelectedItem!.Value);
        Assert.Equal(BinaryEncoding.Hex, Find<IUISelectDropDownList>(tool, "sym-iv-encoding").SelectedItem!.Value);
        foreach (string id in new[] { "sym-key", "sym-iv", "sym-input" })
        {
            var input = Find<IUISingleLineTextInput>(tool, id);
            Assert.False(input.HideCommandBar);
            Assert.False(input.IsReadOnly);
        }
        Assert.Equal(UIHorizontalAlignment.Left, Find<IUISelectDropDownList>(tool, "sym-algorithm").HorizontalAlignment);
    }

    [Theory]
    [InlineData("AES", 0)]
    [InlineData("AES", 1)]
    [InlineData("AES", 2)]
    [InlineData("SM4", 0)]
    [InlineData("SM4", 1)]
    [InlineData("SM4", 2)]
    [InlineData("ChaCha20", 1)]
    public async Task EncodedKeyAndIvRoundTripThroughTheButtons(string algorithm, int encodingValue)
    {
        var tool = new SymmetricTool();
        var encoding = (BinaryEncoding)encodingValue;
        Select(tool, "sym-algorithm", algorithm);
        if (algorithm != "ChaCha20") Select(tool, "sym-mode", "CBC");
        Select(tool, "sym-key-encoding", encoding);
        Select(tool, "sym-iv-encoding", encoding);
        int keyLength = algorithm == "ChaCha20" ? 32 : 16;
        int ivLength = algorithm == "ChaCha20" ? 12 : 16;
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(BinaryText.Encode(Enumerable.Repeat((byte)'k', keyLength).ToArray(), encoding));
        string iv = BinaryText.Encode(Enumerable.Repeat((byte)'i', ivLength).ToArray(), encoding);
        Find<IUISingleLineTextInput>(tool, "sym-iv").Text(iv);
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text("你好 🔑");
        await Click(tool, "sym-encrypt");
        string encrypted = Find<IUIMultiLineTextInput>(tool, "sym-output").Text;
        Assert.NotEmpty(encrypted);
        Assert.Equal(iv, Find<IUISingleLineTextInput>(tool, "sym-iv").Text);
        await Click(tool, "sym-use-output");
        await Click(tool, "sym-decrypt");
        Assert.Equal("你好 🔑", Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
        await Click(tool, "sym-clear");
        Assert.Empty(Find<IUISingleLineTextInput>(tool, "sym-key").Text);
        Assert.Empty(Find<IUISingleLineTextInput>(tool, "sym-iv").Text);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "sym-input").Text);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
    }

    [Fact]
    public void ModeChangesKeepPaddingChoicesValid()
    {
        var tool = new SymmetricTool();
        var padding = Find<IUISelectDropDownList>(tool, "sym-padding");
        Assert.False(padding.IsEnabled);
        Select(tool, "sym-mode", "CBC");
        Assert.True(padding.IsEnabled);
        Assert.Equal("PKCS7", padding.SelectedItem!.Value);
        Select(tool, "sym-algorithm", "ChaCha20");
        Assert.False(padding.IsEnabled);
        Assert.Equal("None", padding.SelectedItem!.Value);
        Assert.Equal("Poly1305", Find<IUISelectDropDownList>(tool, "sym-mode").SelectedItem!.Value);
        Assert.False(Find<IUISelectDropDownList>(tool, "sym-mode").IsEnabled);
        Select(tool, "sym-algorithm", "SM4");
        Assert.True(Find<IUISelectDropDownList>(tool, "sym-mode").IsEnabled);
    }

    [Fact]
    public async Task AutomaticIvsRefreshAndOutputCanBeReencoded()
    {
        var tool = new SymmetricTool();
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(new string('0', 32));
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text("message");
        await Click(tool, "sym-encrypt");
        string firstIv = Find<IUISingleLineTextInput>(tool, "sym-iv").Text;
        string encrypted = Find<IUIMultiLineTextInput>(tool, "sym-output").Text;
        Select(tool, "sym-output-encoding", BinaryEncoding.Hex);
        Assert.Equal(Convert.ToHexString(Convert.FromBase64String(encrypted)), Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
        await Click(tool, "sym-encrypt");
        Assert.NotEqual(firstIv, Find<IUISingleLineTextInput>(tool, "sym-iv").Text);
    }

    [Fact]
    public async Task InvalidIvIsShownWithoutLeavingStaleOutput()
    {
        var tool = new SymmetricTool();
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(new string('0', 32));
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text("message");
        await Click(tool, "sym-encrypt");
        Find<IUISingleLineTextInput>(tool, "sym-iv").Text("00");
        await Click(tool, "sym-encrypt");
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
    }

    private static T Find<T>(SymmetricTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static void Select(SymmetricTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Click(SymmetricTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
}
