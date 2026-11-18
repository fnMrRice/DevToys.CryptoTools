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
    private readonly IUISelectDropDownList _operation = SelectDropDownList("rsa-operation").Title(L("Mode"))
        .WithItems(new[] { "Encrypt", "Decrypt", "Sign", "Verify" }.Select(value => Item(L(value), value)).ToArray()).Select(0);
    private readonly IUISelectDropDownList _padding = Options("rsa-encryption-padding", "Padding", RsaCryptography.EncryptionPaddings);
    private readonly IUISelectDropDownList _hash = Options("rsa-hash", "Hash", RsaCryptography.Hashes);
    private readonly IUISelectDropDownList _signaturePadding = Options("rsa-signature-padding", "SignaturePadding", RsaCryptography.SignaturePaddings);
    private readonly IUISelectDropDownList _source = SelectDropDownList("rsa-public-source").Title(L("PublicKeySource"))
        .WithItems(Item(L("KeyFileSource"), "key"), Item(L("RsaParameterSource"), "parameters")).Select(0);
    private readonly IUISelectDropDownList _publicEncoding = SelectDropDownList("rsa-public-encoding")
        .WithItems(Item("PEM", PublicKeyEncoding.Pem), Item("Base64", PublicKeyEncoding.Base64), Item("Hex", PublicKeyEncoding.Hex)).Select(0);
    private readonly IUISelectDropDownList _parameterEncoding = SelectDropDownList("rsa-parameter-encoding").Title(L("RsaParameterEncoding"))
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
    private readonly IUIGrid _inputPane;
    private readonly IUIButton _run;
    private readonly IUIButton _useOutput;
    private readonly IUIGrid _layout;

    protected override bool IsScrollable => false;
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
        _publicKey.Editor.Title(L("PublicKeyMaterial")).CommandBarExtraContent(_publicEncoding);
        _privateKey = new KeyFileInput("rsa-private", ExecuteAsync, Invalidate, L("RsaPrivateImportHint"));
        _privateKey.Editor.Title(L("PrivateKey"));
        _parameters = Stack("rsa-parameters").Vertical().SmallSpacing().WithChildren(_parameterEncoding,
            Grid().Rows(new UIGridLength(110)).Cells(At(0, 0, _modulus)), _exponent);
        _publicPanel = Stack("rsa-public-panel").Vertical().SmallSpacing().WithChildren(_source,
            Grid().Cells(At(0, 0, _publicKey.View), At(0, 0, _parameters)));
        var keyPanel = Grid("rsa-key-panel").Cells(At(0, 0, _publicPanel), At(0, 0, _privateKey.View));
        var options = Stack().Vertical().MediumSpacing().WithChildren(_operation, _padding, _signaturePadding, _hash);
        var configuration = Grid("rsa-configuration").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(
            At(0, 0, options.AlignVertically(UIVerticalAlignment.Top)), At(0, 1, keyPanel));
        _inputPane = Grid("rsa-input-pane").Rows(Fraction(1), Auto).RowMediumSpacing().Cells(At(0, 0, _input), At(1, 0, _signature));
        var editors = SplitGrid("rsa-editors").Vertical().WithLeftPaneChild(_inputPane).WithRightPaneChild(_output);
        _run = CreateActionButton(L("Encrypt"), Run, "rsa-run").AccentAppearance();
        _useOutput = CreateActionButton(L("UseOutputAsInput"), UseOutputAsInput, "rsa-use-output");
        var actions = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            _run, _useOutput, CreateActionButton(L("Clear"), Clear, "rsa-clear"));
        _layout = Grid("rsa-layout").Rows(Auto, Auto, Fraction(1), Auto).RowMediumSpacing().Cells(
            At(0, 0, configuration), At(1, 0, actions), At(2, 0, editors), At(3, 0, Status));

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
        if (IsSigningOperation) { _padding.Hide(); _signaturePadding.Show(); _hash.Show(); }
        else { _padding.Show(); _signaturePadding.Hide(); _hash.Hide(); }
        bool verify = Selected(_operation) == "Verify";
        if (verify) _signature.Show(); else _signature.Hide();
        _inputPane.Rows(Fraction(2), verify ? Fraction(1) : Auto);
        _run.Text(L(Selected(_operation)));
        if (verify) _useOutput.Disable(); else _useOutput.Enable();
        UpdateSource();
    }

    private void UpdateSource()
    {
        if (IsPublicOperation)
        {
            _publicPanel.Show(); _source.Show(); _privateKey.View.Hide();
            if (Selected(_source) == "parameters") { _parameters.Show(); _publicKey.View.Hide(); }
            else { _parameters.Hide(); _publicKey.View.Show(); }
        }
        else { _publicPanel.Hide(); _source.Hide(); _parameters.Hide(); _privateKey.View.Show(); }
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

    private static IUISelectDropDownList Options(string id, string title, string[] values) => SelectDropDownList(id)
        .Title(L(title)).WithItems(values.Select(value => Item(value, value)).ToArray()).Select(0);
    private static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
