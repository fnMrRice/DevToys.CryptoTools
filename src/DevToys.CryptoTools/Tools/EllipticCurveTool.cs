using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.EllipticCurveTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "EcTitle",
    LongDisplayTitleResourceName = "EcTitle",
    DescriptionResourceName = "EcDescription",
    AccessibleNameResourceName = "EcTitle")]
internal sealed class EllipticCurveTool : CryptoToolBase
{
    private readonly IUISelectDropDownList _operation = SelectDropDownList("ec-operation").Title(L("Mode"))
        .WithItems(new[] { "Encrypt", "Decrypt", "Sign", "Verify" }.Select(value => Item(L(value), value)).ToArray()).Select(0);
    private readonly IUISelectDropDownList _algorithm = SelectDropDownList("ec-algorithm").Title(L("Algorithm"))
        .WithItems(EllipticCurveCryptography.EncryptionAlgorithms.Select(value => Item(value, value)).ToArray()).Select(0);
    private readonly IUISelectDropDownList _source = SelectDropDownList("ec-public-source").Title(L("PublicKeySource"))
        .WithItems(Item(L("KeyFileSource"), "key"), Item(L("CoordinateSource"), "coordinates")).Select(0);
    private readonly IUISelectDropDownList _publicEncoding = SelectDropDownList("ec-public-encoding")
        .WithItems(Item("PEM", PublicKeyEncoding.Pem), Item("Base64", PublicKeyEncoding.Base64), Item("Hex", PublicKeyEncoding.Hex)).Select(0);
    private readonly IUISelectDropDownList _coordinateEncoding = SelectDropDownList("ec-coordinate-encoding").Title(L("CoordinateEncoding"))
        .WithItems(Item("Hex", PublicKeyEncoding.Hex), Item("Base64", PublicKeyEncoding.Base64)).Select(0);
    private readonly IUISingleLineTextInput _sm2Id = SingleLineTextInput("ec-sm2-id").Title(L("Sm2Id")).Text("1234567812345678");
    private readonly IUISingleLineTextInput _x = SingleLineTextInput("ec-x").Title(L("CoordinateXValue")).ShowCommandBar();
    private readonly IUISingleLineTextInput _y = SingleLineTextInput("ec-y").Title(L("CoordinateYValue")).ShowCommandBar();
    private readonly IUIMultiLineTextInput _input = MultiLineTextInput("ec-input").Title(L("Input")).ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _signature = MultiLineTextInput("ec-signature").Title(L("Signature")).ShowCommandBar().CanCopyWhenEditable().Extendable();
    private readonly IUIMultiLineTextInput _output = MultiLineTextInput("ec-output").Title(L("Output")).ReadOnly().ShowCommandBar().Extendable();
    private readonly KeyFileInput _publicKey;
    private readonly KeyFileInput _privateKey;
    private readonly IUIElement _publicPanel;
    private readonly IUIElement _coordinates;
    private readonly IUIGrid _inputPane;
    private readonly IUIButton _run;
    private readonly IUIButton _useOutput;
    private readonly IUIGrid _layout;
    private bool _updating;
    private string _lastEncryption = EllipticCurveCryptography.EncryptionAlgorithms[0];
    private string _lastSigning = EllipticCurveCryptography.SigningAlgorithms[0];

    protected override bool IsScrollable => false;
    protected override IUIElement BuildLayout() => _layout;
    private bool IsPublicOperation => Selected(_operation) is "Encrypt" or "Verify";
    private bool IsSigningOperation => Selected(_operation) is "Sign" or "Verify";

    public EllipticCurveTool()
    {
        _publicKey = new KeyFileInput("ec-public", ExecuteAsync, () =>
        {
            _publicEncoding.Select(0);
            Invalidate();
        }, L("EcPublicImportHint"));
        _publicKey.Editor.Title(L("PublicKeyMaterial")).CommandBarExtraContent(_publicEncoding);
        _privateKey = new KeyFileInput("ec-private", ExecuteAsync, Invalidate, L("EcPrivateImportHint"));
        _privateKey.Editor.Title(L("PrivateKey"));
        _coordinates = Stack("ec-coordinates").Vertical().SmallSpacing().WithChildren(_coordinateEncoding, _x, _y,
            Label().Text(L("CoordinateEncodingHint")).AlignHorizontally(UIHorizontalAlignment.Left));
        _publicPanel = Stack("ec-public-panel").Vertical().SmallSpacing().WithChildren(
            Grid().Cells(At(0, 0, _publicKey.View), At(0, 0, _coordinates)));
        var keyPanel = Grid("ec-key-panel").Cells(At(0, 0, _publicPanel), At(0, 0, _privateKey.View));
        var options = Stack("ec-options").Vertical().MediumSpacing().WithChildren(_operation, _algorithm, _source, _sm2Id);
        var configuration = Grid("ec-configuration").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(
            At(0, 0, options.AlignVertically(UIVerticalAlignment.Top)), At(0, 1, keyPanel));
        _inputPane = Grid("ec-input-pane").Rows(Fraction(1), Auto).RowMediumSpacing().Cells(At(0, 0, _input), At(1, 0, _signature));
        var editors = SplitGrid("ec-editors").Vertical().WithLeftPaneChild(_inputPane).WithRightPaneChild(_output);
        _run = CreateActionButton(L("Encrypt"), Run, "ec-run").AccentAppearance();
        _useOutput = CreateActionButton(L("UseOutputAsInput"), UseOutputAsInput, "ec-use-output");
        var actions = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            _run, _useOutput, CreateActionButton(L("Clear"), Clear, "ec-clear"));
        _layout = Grid("ec-layout").Rows(Auto, Auto, Fraction(1), Auto).RowMediumSpacing().Cells(
            At(0, 0, configuration), At(1, 0, actions), At(2, 0, editors), At(3, 0, Status));

        _operation.OnItemSelected(_ => UpdateOperation());
        _algorithm.OnItemSelected(_ => { if (!_updating) UpdateAlgorithm(); });
        _source.OnItemSelected(_ => { if (!_updating) UpdateSource(); });
        _publicEncoding.OnItemSelected(_ => Invalidate());
        _coordinateEncoding.OnItemSelected(_ => Invalidate());
        foreach (var editor in new IUISingleLineTextInput[] { _publicKey.Editor, _privateKey.Editor, _x, _y, _sm2Id, _input, _signature })
            editor.TextChanged += (_, _) => Invalidate();
        UpdateOperation();
    }

    private void UpdateOperation()
    {
        string previous = Selected(_algorithm);
        bool signing = IsSigningOperation;
        string[] algorithms = signing ? EllipticCurveCryptography.SigningAlgorithms : EllipticCurveCryptography.EncryptionAlgorithms;
        string mapped = previous.StartsWith("ECDH-", StringComparison.Ordinal) ? previous.Replace("ECDH-", "ECDSA-", StringComparison.Ordinal)
            : previous.StartsWith("ECDSA-", StringComparison.Ordinal) ? previous.Replace("ECDSA-", "ECDH-", StringComparison.Ordinal)
            : previous.StartsWith("SM2-", StringComparison.Ordinal) ? "SM2"
            : previous == "SM2" ? (_lastEncryption.StartsWith("SM2-", StringComparison.Ordinal) ? _lastEncryption : "SM2-C1C3C2") : "";
        string selected = algorithms.Contains(previous) ? previous : algorithms.Contains(mapped) ? mapped : signing ? _lastSigning : _lastEncryption;
        _updating = true;
        try { _algorithm.WithItems(algorithms.Select(value => Item(value, value)).ToArray()).Select(Array.IndexOf(algorithms, selected)); }
        finally { _updating = false; }
        UpdateAlgorithm();
        bool verify = Selected(_operation) == "Verify";
        if (verify) _signature.Show(); else _signature.Hide();
        _inputPane.Rows(Fraction(2), verify ? Fraction(1) : Auto);
        _run.Text(L(Selected(_operation)));
        if (verify) _useOutput.Disable(); else _useOutput.Enable();
    }

    private void UpdateAlgorithm()
    {
        if (IsSigningOperation) _lastSigning = Selected(_algorithm); else _lastEncryption = Selected(_algorithm);
        if (IsSigningOperation && Selected(_algorithm) == "SM2") _sm2Id.Show(); else _sm2Id.Hide();
        string previous = Selected(_source);
        bool supportsCoordinates = EcDomains.SupportsCoordinates(Selected(_algorithm));
        _updating = true;
        try
        {
            _source.WithItems(supportsCoordinates
                ? [Item(L("KeyFileSource"), "key"), Item(L("CoordinateSource"), "coordinates")]
                : [Item(L("KeyFileSource"), "key")]).Select(previous == "coordinates" && supportsCoordinates ? 1 : 0);
        }
        finally { _updating = false; }
        UpdateSource();
    }

    private void UpdateSource()
    {
        bool publicKey = IsPublicOperation;
        if (publicKey)
        {
            _publicPanel.Show(); _source.Show(); _privateKey.View.Hide();
            if (Selected(_source) == "coordinates") { _coordinates.Show(); _publicKey.View.Hide(); }
            else { _coordinates.Hide(); _publicKey.View.Show(); }
        }
        else { _publicPanel.Hide(); _source.Hide(); _coordinates.Hide(); _privateKey.View.Show(); }
        Invalidate();
    }

    private string PublicKeyPem() => Selected(_source) == "coordinates"
        ? EllipticCurvePublicKeyInput.FromCoordinates(Selected(_algorithm), _x.Text, _y.Text, (PublicKeyEncoding)_coordinateEncoding.SelectedItem!.Value!)
        : EllipticCurvePublicKeyInput.Decode(Selected(_algorithm), _publicKey.Editor.Text, (PublicKeyEncoding)_publicEncoding.SelectedItem!.Value!);

    private void Run()
    {
        Invalidate();
        string algorithm = Selected(_algorithm);
        string result = Selected(_operation) switch
        {
            "Encrypt" => EllipticCurveCryptography.Encrypt(algorithm, PublicKeyPem(), _input.Text),
            "Decrypt" => EllipticCurveCryptography.Decrypt(algorithm, _privateKey.GetPem(), _input.Text),
            "Sign" => EllipticCurveCryptography.Sign(algorithm, _privateKey.GetPem(), _input.Text, _sm2Id.Text),
            "Verify" => L(EllipticCurveCryptography.Verify(algorithm, PublicKeyPem(), _input.Text, _signature.Text, _sm2Id.Text) ? "Valid" : "Invalid"),
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
        _publicKey.Clear(); _privateKey.Clear(); _x.Text(""); _y.Text(""); _sm2Id.Text("1234567812345678");
        _input.Text(""); _signature.Text(""); Invalidate();
    }

    private static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
