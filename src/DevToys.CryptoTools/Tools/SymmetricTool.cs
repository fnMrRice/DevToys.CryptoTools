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
    private readonly IUISelectDropDownList _algorithm = Options("sym-algorithm", SymmetricAlgorithmCatalog.Algorithms);
    private readonly IUISelectDropDownList _keyLength = SelectDropDownList("sym-key-length");
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
    private readonly IUIButton _generateIv;
    private readonly IUIStack _layout;
    private byte[]? _lastOutput;
    private byte[]? _generatedIv;
    private bool _automaticIv = true;
    private bool _writingIv;

    protected override IUIElement BuildLayout() => _layout;

    public SymmetricTool()
    {
        _algorithm.OnItemSelected(_ => UpdateModes());
        _keyLength.OnItemSelected(_ => Invalidate());
        _key.OnTextChanged(_ => Invalidate());
        _keyEncoding.OnItemSelected(_ => Invalidate());
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

        _algorithm.Title(L("Algorithm"));
        _keyLength.Title(L("KeyLengthBits"));
        _mode.Title(L("Mode"));
        _padding.Title(L("BlockPadding"));
        var settings = Grid("sym-settings").Columns(Fraction(1)).Rows(Auto, Auto, Auto, Auto).RowMediumSpacing().Cells(
            At(0, 0, _algorithm), At(1, 0, _keyLength), At(2, 0, _mode), At(3, 0, _padding));
        var options = settings.AlignVertically(UIVerticalAlignment.Top);
        _generateIv = CreateActionButton(L("GenerateIv"), GenerateIv, "sym-generate-iv").AlignHorizontally(UIHorizontalAlignment.Left);
        var keyPanel = Stack().Vertical().SmallSpacing().WithChildren(_key, PlaceholderTextInput.Wrap(_iv, L("IvHint"), "sym-iv-placeholder"),
            Stack().Horizontal().SmallSpacing().WithChildren(
                CreateActionButton(L("GenerateKey"), GenerateKey, "sym-generate-key"), _generateIv))
            .AlignVertically(UIVerticalAlignment.Top);
        var configuration = Grid("sym-configuration").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing()
            .AlignVertically(UIVerticalAlignment.Top).Cells(At(0, 0, options), At(0, 1, keyPanel));
        var actions = Stack("sym-actions").Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            CreateActionButton(L("Encrypt"), () => Transform(true), "sym-encrypt").AccentAppearance(),
            CreateActionButton(L("Decrypt"), () => Transform(false), "sym-decrypt"),
            CreateActionButton(L("UseOutputAsInput"), UseOutputAsInput, "sym-use-output"),
            CreateActionButton(L("Clear"), Clear, "sym-clear"));
        var editors = SplitGrid("sym-editors").Vertical().WithLeftPaneChild(_input).WithRightPaneChild(_output);
        var editorArea = Grid("sym-editor-area").Rows(new UIGridLength(350)).AlignVertically(UIVerticalAlignment.Top)
            .Cells(Cell().WithChild(editors));
        _layout = Stack("sym-layout").Vertical().MediumSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(configuration, actions, editorArea, Status);
        UpdateModes();
    }

    private string CipherAlgorithm => Selected(_algorithm) + "-" + Selected(_mode);
    private static IUIGridCell At(int row, int column, IUIElement element) => Cell().Row(row).Column(column).WithChild(element);
    private static BinaryEncoding EncodingOf(IUISelectDropDownList choice) => (BinaryEncoding)choice.SelectedItem!.Value!;
    private static IUISelectDropDownList Options(string id, params string[] values) => SelectDropDownList(id)
        .WithItems(values.Select(value => Item(value, value)).ToArray()).Select(0).AlignHorizontally(UIHorizontalAlignment.Stretch);
    private static IUISelectDropDownList EncodingChoice(string id, BinaryEncoding selected) => SelectDropDownList(id)
        .WithItems(Item("Base64", BinaryEncoding.Base64), Item("Hex", BinaryEncoding.Hex), Item(L("Utf8Text"), BinaryEncoding.Text))
        .Select((int)selected).AlignHorizontally(UIHorizontalAlignment.Left);

    private void UpdateModes()
    {
        UpdateKeyLengths();
        string previous = Selected(_mode);
        string[] modes = SymmetricAlgorithmCatalog.Modes(Selected(_algorithm));
        _mode.WithItems(modes.Select(value => Item(value, value)).ToArray()).Select(Math.Max(0, Array.IndexOf(modes, previous)));
        if (modes.Length == 1) _mode.Disable(); else _mode.Enable();
        UpdatePadding();
    }

    private void UpdateKeyLengths()
    {
        string algorithm = Selected(_algorithm);
        int[] bits = SymmetricAlgorithmCatalog.KeyLengths(algorithm).Select(bytes => bytes * 8).ToArray();
        int previous = _keyLength.SelectedItem?.Value is int value ? value : 0;
        int selected = bits.Contains(previous) ? previous : SymmetricAlgorithmCatalog.DefaultKeyLength(algorithm) * 8;
        _keyLength.WithItems(bits.Select(value => Item(value.ToString(System.Globalization.CultureInfo.InvariantCulture), value)).ToArray())
            .Select(Array.IndexOf(bits, selected));
        if (bits.Length > 1) _keyLength.Enable(); else _keyLength.Disable();
    }

    private void UpdatePadding()
    {
        string[] paddings = SymmetricAlgorithmCatalog.PaddingNames(CipherAlgorithm);
        _padding.WithItems(paddings.Select(value => Item(value == "None" ? L("NoPadding") : value, value)).ToArray()).Select(0);
        if (paddings.Length > 1) _padding.Enable(); else _padding.Disable();
        int length = SymmetricCipher.IvLength(CipherAlgorithm);
        _iv.Title(length == 0 ? L("IvNotRequired") : string.Format(System.Globalization.CultureInfo.CurrentCulture, L("IvTitle"), length));
        if (length == 0) { _iv.Disable(); _ivEncoding.Disable(); _generateIv.Disable(); }
        else { _iv.Enable(); _ivEncoding.Enable(); _generateIv.Enable(); }
        if (_automaticIv) { _iv.Text(""); _generatedIv = null; }
        ClearOutput();
    }

    private void Transform(bool encrypt)
    {
        ClearOutput();
        byte[] originalKey = BinaryText.Decode(_key.Text ?? "", EncodingOf(_keyEncoding));
        byte[]? key = null;
        try
        {
            key = SymmetricKeyMaterial.Normalize(Selected(_algorithm), originalKey, (int)_keyLength.SelectedItem!.Value! / 8);
            if (!encrypt && IsLegacyEnvelope(_input.Text ?? ""))
            {
                // Keep ciphertext generated by v0.1.0 readable.
                string plaintext = SymmetricCryptography.Decrypt(CipherAlgorithm, Convert.ToBase64String(key), _input.Text!);
                SetOutput(BinaryText.Decode(plaintext, BinaryEncoding.Text));
                return;
            }
            int ivLength = SymmetricCipher.IvLength(CipherAlgorithm);
            if (encrypt && _automaticIv && ivLength > 0) GenerateIv();
            byte[] iv = ivLength == 0 ? [] : BinaryText.Decode(_iv.Text ?? "", EncodingOf(_ivEncoding));
            byte[] input = BinaryText.Decode(_input.Text ?? "", EncodingOf(_inputEncoding));
            var padding = Enum.Parse<PaddingMode>(Selected(_padding));
            SetOutput(SymmetricCipher.Transform(encrypt, CipherAlgorithm, key, iv, input, padding));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalKey);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    private void GenerateKey()
    {
        byte[] key = RandomNumberGenerator.GetBytes((int)_keyLength.SelectedItem!.Value! / 8);
        try
        {
            // Random binary keys must retain their full entropy; arbitrary bytes
            // cannot safely be round-tripped through a UTF-8 text field.
            if (EncodingOf(_keyEncoding) == BinaryEncoding.Text) _keyEncoding.Select((int)BinaryEncoding.Hex);
            _key.Text(BinaryText.Encode(key, EncodingOf(_keyEncoding)));
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

    private static bool IsLegacyEnvelope(string text)
    {
        if (!text.TrimStart().StartsWith('{')) return false;
        try
        {
            var envelope = System.Text.Json.JsonSerializer.Deserialize<SymmetricEnvelope>(text,
                new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
            return envelope is not null && envelope.Version > 0 && SymmetricCryptography.Algorithms.Contains(envelope.Algorithm)
                && envelope.Nonce is not null && envelope.Tag is not null && envelope.Ciphertext is not null;
        }
        catch (System.Text.Json.JsonException) { return false; }
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

    private void Invalidate() { ClearOutput(); Status.Hide(); }

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
