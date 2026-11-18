using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class SymmetricToolTests
{
    [Fact]
    public void UsesResizableEditorsAndHexDefaults()
    {
        var tool = new SymmetricTool();
        Assert.True(tool.View.IsScrollable);
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
        foreach (string id in new[] { "sym-algorithm", "sym-mode", "sym-padding" })
            Assert.Equal(UIHorizontalAlignment.Stretch, Find<IUISelectDropDownList>(tool, id).HorizontalAlignment);
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
        Assert.True(Find<IUISelectDropDownList>(tool, "sym-mode").IsEnabled);
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

    [Theory]
    [InlineData("Camellia", "CTR", 16, 16)]
    [InlineData("ARIA", "CCM", 16, 12)]
    [InlineData("Twofish", "EAX", 32, 16)]
    [InlineData("Serpent", "CFB8", 16, 16)]
    [InlineData("Blowfish", "CBC", 16, 8)]
    [InlineData("DES", "ECB", 8, 0)]
    [InlineData("Salsa20", "Raw", 32, 8)]
    public async Task ExpandedAlgorithmAndModeChoicesReachTheCipher(string algorithm, string mode, int keyLength, int ivLength)
    {
        var tool = new SymmetricTool();
        Select(tool, "sym-algorithm", algorithm);
        Select(tool, "sym-mode", mode);
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(Convert.ToHexString(Enumerable.Repeat((byte)'k', keyLength).ToArray()));
        if (ivLength > 0) Find<IUISingleLineTextInput>(tool, "sym-iv").Text(Convert.ToHexString(new byte[ivLength]));
        else
        {
            Assert.False(Find<IUISingleLineTextInput>(tool, "sym-iv").IsEnabled);
            Assert.False(Find<IUIButton>(tool, "sym-generate-iv").IsEnabled);
        }
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text("expanded modes 🔑");
        await Click(tool, "sym-encrypt");
        Assert.NotEmpty(Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
        await Click(tool, "sym-use-output");
        await Click(tool, "sym-decrypt");
        Assert.Equal("expanded modes 🔑", Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
    }

    [Fact]
    public void AlgorithmsOnlyOfferCompatibleModesAndPaddings()
    {
        var tool = new SymmetricTool();
        Select(tool, "sym-mode", "GCM");
        Select(tool, "sym-algorithm", "DES");
        var mode = Find<IUISelectDropDownList>(tool, "sym-mode");
        Assert.DoesNotContain(mode.Items!, item => Equals(item.Value, "GCM") || Equals(item.Value, "CCM"));
        Select(tool, "sym-mode", "CTR");
        Assert.False(Find<IUISelectDropDownList>(tool, "sym-padding").IsEnabled);
        Select(tool, "sym-mode", "CBC");
        Assert.True(Find<IUISelectDropDownList>(tool, "sym-padding").Items!.Length >= 5);
    }

    [Fact]
    public async Task RawTextCiphertextStartingWithBraceIsNotMisreadAsLegacyJson()
    {
        var tool = new SymmetricTool();
        Select(tool, "sym-mode", "CBC");
        Select(tool, "sym-padding", "None");
        Select(tool, "sym-output-encoding", BinaryEncoding.Hex);
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(new string('0', 32));
        Find<IUISingleLineTextInput>(tool, "sym-iv").Text(new string('0', 32));
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text("{0123456789ABCD}");
        await Click(tool, "sym-decrypt");
        Assert.Equal(32, Find<IUIMultiLineTextInput>(tool, "sym-output").Text.Length);
    }

    [Fact]
    public async Task RecognizedLegacyEnvelopeStillDecryptsWithItsStoredIv()
    {
        var tool = new SymmetricTool();
        byte[] key = new byte[16];
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(Convert.ToHexString(key));
        string legacy = SymmetricCryptography.Encrypt("AES-GCM", Convert.ToBase64String(key), "legacy message");
        Select(tool, "sym-key-length", 128);
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text(legacy);
        Select(tool, "sym-output-encoding", BinaryEncoding.Text);
        await Click(tool, "sym-decrypt");
        Assert.Equal("legacy message", Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
    }

    [Fact]
    public void KeyLengthsFollowAlgorithmAndStayExplicitWhenKeyTextChanges()
    {
        var tool = new SymmetricTool();
        var length = Find<IUISelectDropDownList>(tool, "sym-key-length");
        Assert.Equal(new[] { 128, 192, 256 }, length.Items!.Select(item => (int)item.Value!));
        Select(tool, "sym-key-length", 128);
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(new string('1', 64));
        Assert.Equal(128, length.SelectedItem!.Value);
        Select(tool, "sym-algorithm", "SM4");
        Assert.Single(length.Items!);
        Assert.Equal(128, length.SelectedItem!.Value);
        Assert.False(length.IsEnabled);
        Select(tool, "sym-algorithm", "ChaCha20");
        Assert.Equal(256, length.SelectedItem!.Value);
        Select(tool, "sym-algorithm", "Blowfish");
        Assert.Equal(32, length.Items!.Min(item => (int)item.Value!));
        Assert.Equal(448, length.Items!.Max(item => (int)item.Value!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    public async Task SelectedLengthPadsOrTruncatesDecodedKeyWithoutChangingInput(int sourceBytes)
    {
        var tool = new SymmetricTool();
        Select(tool, "sym-mode", "ECB");
        Select(tool, "sym-padding", "None");
        Select(tool, "sym-key-length", 128);
        byte[] original = Enumerable.Range(1, sourceBytes).Select(value => (byte)value).ToArray();
        string keyText = Convert.ToHexString(original);
        Find<IUISingleLineTextInput>(tool, "sym-key").Text(keyText);
        const string message = "0123456789abcdef";
        Find<IUIMultiLineTextInput>(tool, "sym-input").Text(message);
        await Click(tool, "sym-encrypt");
        byte[] expectedKey = new byte[16];
        original.AsSpan(0, Math.Min(16, original.Length)).CopyTo(expectedKey);
        string expected = Convert.ToBase64String(SymmetricCipher.Transform(true, "AES-ECB", expectedKey, [], System.Text.Encoding.UTF8.GetBytes(message)));
        Assert.Equal(expected, Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
        Assert.Equal(keyText, Find<IUISingleLineTextInput>(tool, "sym-key").Text);
        await Click(tool, "sym-use-output");
        await Click(tool, "sym-decrypt");
        Assert.Equal(message, Find<IUIMultiLineTextInput>(tool, "sym-output").Text);
    }

    [Fact]
    public async Task RandomKeyUsesSelectedSizeAndAReversibleBinaryEncoding()
    {
        var tool = new SymmetricTool();
        Select(tool, "sym-key-length", 192);
        Select(tool, "sym-key-encoding", BinaryEncoding.Base64);
        await Click(tool, "sym-generate-key");
        string first = Find<IUISingleLineTextInput>(tool, "sym-key").Text;
        Assert.Equal(24, Convert.FromBase64String(first).Length);
        await Click(tool, "sym-generate-key");
        Assert.NotEqual(first, Find<IUISingleLineTextInput>(tool, "sym-key").Text);
        Select(tool, "sym-key-encoding", BinaryEncoding.Text);
        await Click(tool, "sym-generate-key");
        Assert.Equal(BinaryEncoding.Hex, Find<IUISelectDropDownList>(tool, "sym-key-encoding").SelectedItem!.Value);
        Assert.Equal(24, Convert.FromHexString(Find<IUISingleLineTextInput>(tool, "sym-key").Text).Length);
    }

    private static T Find<T>(SymmetricTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static void Select(SymmetricTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Click(SymmetricTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
}
