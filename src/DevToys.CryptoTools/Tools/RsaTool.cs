using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.RsaTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "RsaTitle",
    LongDisplayTitleResourceName = "RsaTitle",
    DescriptionResourceName = "RsaDescription",
    AccessibleNameResourceName = "RsaTitle")]
internal sealed class RsaTool : CryptoToolBase
{
    private readonly IUISelectDropDownList _operation = SelectDropDownList("rsa-operation")
        .WithItems(new[] { "Encrypt", "Decrypt", "Sign", "Verify" }.Select(value => Item(L(value), value)).ToArray()).Select(0);
    private readonly IUISelectDropDownList _padding = Options("rsa-encryption-padding", RsaCryptography.EncryptionPaddings);
    private readonly IUISelectDropDownList _hash = Options("rsa-hash", RsaCryptography.Hashes);
    private readonly IUISelectDropDownList _signaturePadding = Options("rsa-signature-padding", RsaCryptography.SignaturePaddings);
    private readonly IUISelectDropDownList _source = SelectDropDownList("rsa-public-source")
        .WithItems(Item(L("KeyFileSource"), "key"), Item(L("RsaParameterSource"), "parameters")).Select(0);
    private readonly IUISelectDropDownList _publicEncoding = SelectDropDownList("rsa-public-encoding")
        .WithItems(Item("PEM", PublicKeyEncoding.Pem), Item("Base64", PublicKeyEncoding.Base64), Item("Hex", PublicKeyEncoding.Hex)).Select(0);
    private readonly IUISelectDropDownList _parameterEncoding = SelectDropDownList("rsa-parameter-encoding")
        .WithItems(Item("Hex", PublicKeyEncoding.Hex), Item("Base64", PublicKeyEncoding.Base64)).Select(0);
    private readonly IUIMultiLineTextInput _modulus = MultiLineTextInput("rsa-modulus").Title(L("RsaModulus")).ShowCommandBar().Extendable();
    private readonly IUISingleLineTextInput _exponent = SingleLineTextInput("rsa-exponent").Title(L("RsaExponent")).ShowCommandBar();
    private readonly IUIMultiLineTextInput _input = MultiLineTextInput("rsa-input").Title(L("Input")).ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _signature = MultiLineTextInput("rsa-signature").Title(L("Signature")).ShowCommandBar().CanCopyWhenEditable().Extendable();
    private readonly IUIMultiLineTextInput _output = MultiLineTextInput("rsa-output").Title(L("Output")).ReadOnly().ShowCommandBar().Extendable();
    private readonly KeyFileInput _publicKey;
    private readonly KeyFileInput _privateKey;
    private readonly IUIElement _publicPanel;
    private readonly IUIElement _parameters;
    private readonly IUISetting _paddingSetting;
    private readonly IUISetting _signaturePaddingSetting;
    private readonly IUISetting _hashSetting;
    private readonly IUISetting _sourceSetting;
    private readonly IUISetting _publicEncodingSetting;
    private readonly IUISetting _parameterEncodingSetting;
    private readonly IUIGrid _inputPane;
    private readonly IUIButton _run;
    private readonly IUIButton _useOutput;
    private readonly IUIStack _layout;

    protected override IUIElement BuildLayout() => _layout;
    private bool IsPublicOperation => Selected(_operation) is "Encrypt" or "Verify";
    private bool IsSigningOperation => Selected(_operation) is "Sign" or "Verify";

    public RsaTool()
    {
        _publicKey = new KeyFileInput("rsa-public", ExecuteAsync, () =>
        {
            _publicEncoding.Select(0);
            Invalidate();
        }, L("RsaPublicImportHint"));
        _publicKey.Editor.Title(L("PublicKeyMaterial"));
        _privateKey = new KeyFileInput("rsa-private", ExecuteAsync, Invalidate, L("RsaPrivateImportHint"));
        _privateKey.Editor.Title(L("PrivateKey"));
        _parameters = Stack("rsa-parameters").Vertical().SmallSpacing().AlignVertically(UIVerticalAlignment.Top).WithChildren(
            Grid().Rows(new UIGridLength(180)).AlignVertically(UIVerticalAlignment.Top).Cells(At(0, 0, _modulus)), _exponent);
        _publicPanel = Stack("rsa-public-panel").Vertical().SmallSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(_publicKey.View, _parameters);
        var keyPanel = Stack("rsa-key-panel").Vertical().SmallSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(_publicPanel, _privateKey.View);
        _paddingSetting = Parameter("rsa-encryption-padding-setting", "Padding", _padding);
        _signaturePaddingSetting = Parameter("rsa-signature-padding-setting", "SignaturePadding", _signaturePadding);
        _hashSetting = Parameter("rsa-hash-setting", "Hash", _hash);
        _sourceSetting = Parameter("rsa-public-source-setting", "PublicKeySource", _source);
        _publicEncodingSetting = Parameter("rsa-public-encoding-setting", "PublicKeyEncoding", _publicEncoding);
        _parameterEncodingSetting = Parameter("rsa-parameter-encoding-setting", "RsaParameterEncoding", _parameterEncoding);
        var options = SettingGroup("rsa-parameter-settings").Title(L("CryptoParameters")).Description(L("RsaNote"))
            .Icon("FluentSystemIcons", '\uE670').WithSettings(_paddingSetting, _signaturePaddingSetting, _hashSetting,
                _sourceSetting, _publicEncodingSetting, _parameterEncodingSetting);
        var configuration = Stack("rsa-configuration").Vertical().SmallSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(Parameter("rsa-operation-setting", "Mode", _operation), options);
        _inputPane = Grid("rsa-input-pane").Rows(Fraction(1), Auto).RowNoSpacing()
            .Cells(At(0, 0, _input), At(1, 0, _signature));
        var editors = SplitGrid("rsa-editors").Vertical().WithLeftPaneChild(_inputPane).WithRightPaneChild(_output);
        var editorArea = Grid("rsa-editor-area").Rows(new UIGridLength(350)).AlignVertically(UIVerticalAlignment.Top)
            .Cells(At(0, 0, editors));
        _run = CreateActionButton(L("Encrypt"), Run, "rsa-run").AccentAppearance();
        _useOutput = CreateActionButton(L("UseOutputAsInput"), UseOutputAsInput, "rsa-use-output");
        var actions = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            _run, _useOutput, CreateActionButton(L("Clear"), Clear, "rsa-clear"));
        _layout = Stack("rsa-layout").Vertical().MediumSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(configuration, keyPanel, actions, editorArea, Status);

        _operation.OnItemSelected(_ => UpdateOperation());
        _source.OnItemSelected(_ => UpdateSource());
        foreach (var choice in new[] { _padding, _signaturePadding, _hash, _publicEncoding, _parameterEncoding })
            choice.OnItemSelected(_ => Invalidate());
        foreach (var editor in new IUISingleLineTextInput[] { _publicKey.Editor, _privateKey.Editor, _modulus, _exponent, _input, _signature })
            editor.TextChanged += (_, _) => Invalidate();
        UpdateOperation();
    }

    private void UpdateOperation()
    {
        SetVisible(_paddingSetting, _padding, !IsSigningOperation);
        SetVisible(_signaturePaddingSetting, _signaturePadding, IsSigningOperation);
        SetVisible(_hashSetting, _hash, IsSigningOperation);
        bool verify = Selected(_operation) == "Verify";
        if (verify) _signature.Show(); else _signature.Hide();
        // This grid intentionally fills the bounded editor region. Equal rows
        // leave enough room for both native editor headers and their minimum height.
        _inputPane.Rows(Fraction(1), verify ? Fraction(1) : Auto);
        if (verify) _inputPane.RowSmallSpacing(); else _inputPane.RowNoSpacing();
        _run.Text(L(Selected(_operation)));
        if (verify) _useOutput.Disable(); else _useOutput.Enable();
        UpdateSource();
    }

    private void UpdateSource()
    {
        bool parameters = IsPublicOperation && Selected(_source) == "parameters";
        SetVisible(_sourceSetting, _source, IsPublicOperation);
        SetVisible(_publicEncodingSetting, _publicEncoding, IsPublicOperation && !parameters);
        SetVisible(_parameterEncodingSetting, _parameterEncoding, parameters);
        if (IsPublicOperation)
        {
            _publicPanel.Show(); _privateKey.View.Hide();
            if (parameters) { _parameters.Show(); _publicKey.View.Hide(); }
            else { _parameters.Hide(); _publicKey.View.Show(); }
        }
        else { _publicPanel.Hide(); _parameters.Hide(); _privateKey.View.Show(); }
        Invalidate();
    }

    private string PublicKeyPem() => Selected(_source) == "parameters"
        ? RsaPublicKeyInput.FromParameters(_modulus.Text, _exponent.Text, (PublicKeyEncoding)_parameterEncoding.SelectedItem!.Value!)
        : RsaPublicKeyInput.Decode(_publicKey.Editor.Text, (PublicKeyEncoding)_publicEncoding.SelectedItem!.Value!);

    private void Run()
    {
        Invalidate();
        string result = Selected(_operation) switch
        {
            "Encrypt" => RsaCryptography.Encrypt(PublicKeyPem(), _input.Text, Selected(_padding)),
            "Decrypt" => RsaCryptography.Decrypt(_privateKey.GetPem(), _input.Text, Selected(_padding)),
            "Sign" => RsaCryptography.Sign(_privateKey.GetPem(), _input.Text, Selected(_hash), Selected(_signaturePadding)),
            "Verify" => L(RsaCryptography.Verify(PublicKeyPem(), _input.Text, _signature.Text, Selected(_hash), Selected(_signaturePadding)) ? "Valid" : "Invalid"),
            _ => throw new ArgumentException(L("InvalidAlgorithm"))
        };
        _output.Text(result);
    }

    private void UseOutputAsInput()
    {
        string output = _output.Text;
        if (string.IsNullOrEmpty(output)) return;
        if (Selected(_operation) == "Sign") { _operation.Select(3); _signature.Text(output); }
        else if (Selected(_operation) == "Encrypt") { _operation.Select(1); _input.Text(output); }
        else if (Selected(_operation) == "Decrypt") { _operation.Select(0); _input.Text(output); }
        Invalidate();
    }

    private void Invalidate() { _output.Text(""); Status.Hide(); }
    private void Clear()
    {
        _publicKey.Clear(); _privateKey.Clear(); _modulus.Text(""); _exponent.Text("");
        _input.Text(""); _signature.Text(""); Invalidate();
    }

    private static IUISelectDropDownList Options(string id, string[] values) => SelectDropDownList(id)
        .WithItems(values.Select(value => Item(value, value)).ToArray()).Select(0);
    private static IUISetting Parameter(string id, string title, IUIElement input) => Setting(id).Title(L(title))
        .Icon("FluentSystemIcons", '\uE670').InteractiveElement(input);
    private static void SetVisible(IUIElement setting, IUIElement input, bool visible)
    {
        if (visible) { setting.Show(); input.Show(); }
        else { setting.Hide(); input.Hide(); }
    }
    private static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
