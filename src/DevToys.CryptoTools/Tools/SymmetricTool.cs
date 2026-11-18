using System.ComponentModel.Composition;
using System.Security.Cryptography;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.SymmetricTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "SymTitle",
    LongDisplayTitleResourceName = "SymTitle",
    DescriptionResourceName = "SymDescription",
    AccessibleNameResourceName = "SymTitle")]
internal sealed class SymmetricTool : CryptoToolBase
{
    private readonly IUISelectDropDownList _algorithm = Options("sym-algorithm", "AES", "SM4", "ChaCha20");
    private readonly IUISelectDropDownList _mode = Options("sym-mode", "GCM", "CBC");
    private readonly IUISelectDropDownList _padding = Options("sym-padding", "None");
    private readonly IUISelectDropDownList _keyEncoding = EncodingChoice("sym-key-encoding", BinaryEncoding.Hex);
    private readonly IUISelectDropDownList _ivEncoding = EncodingChoice("sym-iv-encoding", BinaryEncoding.Hex);
    private readonly IUISelectDropDownList _inputEncoding = EncodingChoice("sym-input-encoding", BinaryEncoding.Text);
    private readonly IUISelectDropDownList _outputEncoding = EncodingChoice("sym-output-encoding", BinaryEncoding.Base64);
    private readonly IUISingleLineTextInput _key = SingleLineTextInput("sym-key").Title(L("Key")).ShowCommandBar();
    private readonly IUISingleLineTextInput _iv = SingleLineTextInput("sym-iv").ShowCommandBar().CanCopyWhenEditable();
    private readonly IUIMultiLineTextInput _input = MultiLineTextInput("sym-input").Title(L("Input")).ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _output = MultiLineTextInput("sym-output").Title(L("Output")).ReadOnly().ShowCommandBar().Extendable();
    private readonly IUILabel _modeHint = Label("sym-mode-hint").AlignHorizontally(UIHorizontalAlignment.Left);
    private readonly IUIGrid _layout;
    private byte[]? _lastOutput;
    private byte[]? _generatedIv;
    private bool _automaticIv = true;
    private bool _writingIv;

    protected override bool IsScrollable => false;
    protected override IUIElement BuildLayout() => _layout;

    public SymmetricTool()
    {
        _algorithm.OnItemSelected(_ => UpdateModes());
        _mode.OnItemSelected(_ => UpdatePadding());
        _iv.OnTextChanged(text =>
        {
            if (!_writingIv)
            {
                _automaticIv = string.IsNullOrEmpty(text);
                _generatedIv = null;
            }
        });
        _ivEncoding.OnItemSelected(_ =>
        {
            if (_automaticIv && _generatedIv is not null) Execute(() => WriteIv(_generatedIv));
        });
        _outputEncoding.OnItemSelected(_ =>
        {
            if (_lastOutput is not null) Execute(() => RenderOutput(_lastOutput));
        });
        _key.CommandBarExtraContent(_keyEncoding);
        _iv.CommandBarExtraContent(_ivEncoding);
        _input.CommandBarExtraContent(_inputEncoding);
        _output.CommandBarExtraContent(Stack().Horizontal().SmallSpacing().WithChildren(
            _outputEncoding, CreateActionButton(L("Clear"), ClearOutput, "sym-clear-output")));

        var settings = Grid("sym-settings").Columns(Auto, Auto, Fraction(1)).Rows(Auto, Auto, Auto).RowMediumSpacing().ColumnMediumSpacing().Cells(
            At(0, 0, Label().Text(L("Algorithm")).AlignHorizontally(UIHorizontalAlignment.Left)), At(0, 1, _algorithm),
            At(1, 0, Label().Text(L("Mode")).AlignHorizontally(UIHorizontalAlignment.Left)), At(1, 1, _mode),
            At(2, 0, Label().Text(L("BlockPadding")).AlignHorizontally(UIHorizontalAlignment.Left)), At(2, 1, _padding));
        var options = Stack().Vertical().MediumSpacing().WithChildren(settings, _modeHint).AlignVertically(UIVerticalAlignment.Top);
        var keyPanel = Stack().Vertical().SmallSpacing().WithChildren(_key, _iv,
            Stack().Horizontal().MediumSpacing().WithChildren(
                CreateActionButton(L("GenerateIv"), GenerateIv, "sym-generate-iv"),
                Label().Text(L("IvHint")).AlignHorizontally(UIHorizontalAlignment.Left)))
            .AlignVertically(UIVerticalAlignment.Top);
        var configuration = Grid("sym-configuration").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(At(0, 0, options), At(0, 1, keyPanel));
        var actions = Stack("sym-actions").Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            CreateActionButton(L("Encrypt"), () => Transform(true), "sym-encrypt").AccentAppearance(),
            CreateActionButton(L("Decrypt"), () => Transform(false), "sym-decrypt"),
            CreateActionButton(L("UseOutputAsInput"), UseOutputAsInput, "sym-use-output"),
            CreateActionButton(L("Clear"), Clear, "sym-clear"));
        var editors = SplitGrid("sym-editors").Vertical().WithLeftPaneChild(_input).WithRightPaneChild(_output);
        _layout = Grid("sym-layout").Rows(Auto, Auto, Fraction(1), Auto).RowMediumSpacing().Cells(
            At(0, 0, configuration), At(1, 0, actions), At(2, 0, editors), At(3, 0, Status));
        UpdatePadding();
    }

    private string CipherAlgorithm => Selected(_algorithm) == "ChaCha20" ? "ChaCha20-Poly1305" : Selected(_algorithm) + "-" + Selected(_mode);
    private static IUIGridCell At(int row, int column, IUIElement element) => Cell().Row(row).Column(column).WithChild(element);
    private static BinaryEncoding EncodingOf(IUISelectDropDownList choice) => (BinaryEncoding)choice.SelectedItem!.Value!;
    private static IUISelectDropDownList Options(string id, params string[] values) => SelectDropDownList(id)
        .WithItems(values.Select(value => Item(value, value)).ToArray()).Select(0).AlignHorizontally(UIHorizontalAlignment.Left);
    private static IUISelectDropDownList EncodingChoice(string id, BinaryEncoding selected) => SelectDropDownList(id)
        .WithItems(Item("Base64", BinaryEncoding.Base64), Item("Hex", BinaryEncoding.Hex), Item(L("Utf8Text"), BinaryEncoding.Text))
        .Select((int)selected).AlignHorizontally(UIHorizontalAlignment.Left);

    private void UpdateModes()
    {
        string previous = Selected(_mode);
        string[] modes = Selected(_algorithm) == "ChaCha20" ? ["Poly1305"] : ["GCM", "CBC"];
        _mode.WithItems(modes.Select(value => Item(value, value)).ToArray()).Select(Math.Max(0, Array.IndexOf(modes, previous)));
        if (modes.Length == 1) _mode.Disable(); else _mode.Enable();
        UpdatePadding();
    }

    private void UpdatePadding()
    {
        bool cbc = Selected(_mode) == "CBC";
        _padding.WithItems(cbc ? [Item("PKCS7", "PKCS7"), Item(L("NoPadding"), "None")] : [Item(L("NoPadding"), "None")]).Select(0);
        if (cbc) _padding.Enable(); else _padding.Disable();
        int length = SymmetricCipher.IvLength(CipherAlgorithm);
        _iv.Title(string.Format(System.Globalization.CultureInfo.CurrentCulture, L("IvTitle"), length));
        _modeHint.Text(L(cbc ? "CbcHint" : "AuthenticatedHint"));
        if (_automaticIv) { _iv.Text(""); _generatedIv = null; }
        ClearOutput();
    }

    private void Transform(bool encrypt)
    {
        ClearOutput();
        byte[] key = BinaryText.Decode(_key.Text ?? "", EncodingOf(_keyEncoding));
        try
        {
            if (!encrypt && (_input.Text ?? "").TrimStart().StartsWith('{'))
            {
                // Keep ciphertext generated by v0.1.0 readable.
                string plaintext = SymmetricCryptography.Decrypt(CipherAlgorithm, Convert.ToBase64String(key), _input.Text!);
                SetOutput(BinaryText.Decode(plaintext, BinaryEncoding.Text));
                return;
            }
            if (encrypt && _automaticIv) GenerateIv();
            byte[] iv = BinaryText.Decode(_iv.Text ?? "", EncodingOf(_ivEncoding));
            byte[] input = BinaryText.Decode(_input.Text ?? "", EncodingOf(_inputEncoding));
            var padding = Selected(_padding) == "PKCS7" ? PaddingMode.PKCS7 : PaddingMode.None;
            SetOutput(SymmetricCipher.Transform(encrypt, CipherAlgorithm, key, iv, input, padding));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private void GenerateIv()
    {
        // Printable random text is still generated by a cryptographic random source.
        int length = SymmetricCipher.IvLength(CipherAlgorithm);
        byte[] iv = EncodingOf(_ivEncoding) == BinaryEncoding.Text
            ? System.Text.Encoding.ASCII.GetBytes(RandomNumberGenerator.GetString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", length))
            : RandomNumberGenerator.GetBytes(length);
        _automaticIv = true;
        _generatedIv = iv;
        WriteIv(iv);
    }

    private void WriteIv(byte[] iv)
    {
        _writingIv = true;
        try { _iv.Text(BinaryText.Encode(iv, EncodingOf(_ivEncoding))); }
        finally { _writingIv = false; }
    }

    private void SetOutput(byte[] bytes) { _lastOutput = bytes; RenderOutput(bytes); }
    private void RenderOutput(byte[] bytes) { _output.Text(""); _output.Text(BinaryText.Encode(bytes, EncodingOf(_outputEncoding))); }
    private void ClearOutput()
    {
        if (_lastOutput is not null) CryptographicOperations.ZeroMemory(_lastOutput);
        _lastOutput = null;
        _output.Text("");
    }

    private void UseOutputAsInput()
    {
        if (string.IsNullOrEmpty(_output.Text)) return;
        var inputEncoding = EncodingOf(_inputEncoding);
        _input.Text(_output.Text);
        _inputEncoding.Select((int)EncodingOf(_outputEncoding));
        _outputEncoding.Select((int)inputEncoding);
        ClearOutput();
    }

    private void Clear() { _key.Text(""); _iv.Text(""); _input.Text(""); ClearOutput(); }
}
