using System.ComponentModel.Composition;
using System.Globalization;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.CrcTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = PredefinedCommonToolGroupNames.Generators,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "CrcTitle", LongDisplayTitleResourceName = "CrcTitle",
    DescriptionResourceName = "CrcDescription", AccessibleNameResourceName = "CrcTitle")]
internal sealed class CrcTool : CryptoToolBase
{
    private readonly IUISelectDropDownList _preset = SelectDropDownList("crc-preset").Title(L("CrcPreset"))
        .WithItems([.. CrcCalculator.Presets.Select(p => Item(p.Name, p.Name)), Item(L("CrcCustom"), "custom")]).Select(0);
    private readonly IUINumberInput _width = NumberInput("crc-width", 1, 64, 1).Title(L("CrcWidth")).Value(32);
    private readonly IUISingleLineTextInput _polynomial = SingleLineTextInput("crc-polynomial").Title(L("CrcPolynomial")).ShowCommandBar();
    private readonly IUISingleLineTextInput _initial = SingleLineTextInput("crc-initial").Title(L("CrcInitial")).ShowCommandBar();
    private readonly IUISingleLineTextInput _xorOut = SingleLineTextInput("crc-xor-out").Title(L("CrcXorOut")).ShowCommandBar();
    private readonly IUISwitch _reflectInput = Switch("crc-ref-in").OnText(L("CertEnabled")).OffText(L("CertDisabled"));
    private readonly IUISwitch _reflectOutput = Switch("crc-ref-out").OnText(L("CertEnabled")).OffText(L("CertDisabled"));
    private readonly IUISingleLineTextInput _check = SingleLineTextInput("crc-check").Title(L("CrcCheck")).ReadOnly().ShowCommandBar();
    private readonly IUISelectDropDownList _inputEncoding = SelectDropDownList("crc-input-encoding")
        .WithItems(Item(L("Utf8Text"), BinaryEncoding.Text), Item("Hex", BinaryEncoding.Hex), Item("Base64", BinaryEncoding.Base64)).Select(0);
    private readonly IUISelectDropDownList _outputFormat = SelectDropDownList("crc-output-format").Title(L("CrcOutputFormat"))
        .WithItems(Item("Hex", "hex"), Item(L("CrcDecimal"), "decimal"), Item(L("CrcBinary"), "binary"), Item(L("CrcBase64"), "base64")).Select(0);
    private readonly IUIMultiLineTextInput _input = MultiLineTextInput("crc-input").Title(L("Input")).Text("123456789").ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _output = MultiLineTextInput("crc-output").Title(L("Output")).ReadOnly().ShowCommandBar().Extendable();
    private readonly IUIGrid _layout;
    private bool _applyingPreset;
    private (ulong Value, int Width)? _lastResult;

    protected override bool IsScrollable => false;
    protected override IUIElement BuildLayout() => _layout;

    public CrcTool()
    {
        _input.CommandBarExtraContent(_inputEncoding);
        _preset.OnItemSelected(_ => ApplyPreset());
        foreach (var field in new[] { _polynomial, _initial, _xorOut }) field.TextChanged += (_, _) => ParametersChanged();
        _width.ValueChanged += (_, _) => ParametersChanged();
        _reflectInput.IsOnChanged += (_, _) => ParametersChanged();
        _reflectOutput.IsOnChanged += (_, _) => ParametersChanged();
        _input.TextChanged += (_, _) => Invalidate();
        _inputEncoding.OnItemSelected(_ => Invalidate());
        _outputFormat.OnItemSelected(_ =>
        {
            if (_lastResult is { } result) Execute(() => _output.Text(Format(result.Value, result.Width)));
        });
        var left = Stack().Vertical().SmallSpacing().WithChildren(_preset, _width, _polynomial);
        var right = Stack().Vertical().SmallSpacing().WithChildren(_initial, _xorOut,
            Grid().Columns(Fraction(1), Fraction(1)).ColumnMediumSpacing().Cells(
                At(0, 0, Setting().Title(L("CrcReflectInput")).InteractiveElement(_reflectInput)),
                At(0, 1, Setting().Title(L("CrcReflectOutput")).InteractiveElement(_reflectOutput))), _check, _outputFormat);
        var configuration = Grid("crc-configuration").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(At(0, 0, left), At(0, 1, right));
        var actions = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            CreateActionButton(L("CrcCalculate"), Calculate, "crc-calculate").AccentAppearance(),
            CreateActionButton(L("Clear"), () => { _input.Text(""); Invalidate(); }, "crc-clear"));
        var editors = SplitGrid("crc-editors").Vertical().WithLeftPaneChild(_input).WithRightPaneChild(_output);
        _layout = Grid("crc-layout").Rows(Auto, Auto, Auto, Fraction(1), Auto).RowMediumSpacing().Cells(
            At(0, 0, configuration), At(1, 0, Label().Text(L("CrcPolynomialHint")).AlignHorizontally(UIHorizontalAlignment.Left)),
            At(2, 0, actions), At(3, 0, editors), At(4, 0, Status));
        var defaultPreset = _preset.Items!.First(item => Equals(item.Value, "CRC-32/ISO-HDLC"));
        _preset.Select(defaultPreset);
        ApplyPreset();
    }

    private void ApplyPreset()
    {
        Invalidate();
        var preset = CrcCalculator.Presets.FirstOrDefault(p => p.Name == Selected(_preset));
        if (preset is null) { _check.Text(""); return; }
        _applyingPreset = true;
        try
        {
            var parameters = preset.Parameters;
            _width.Value(parameters.Width);
            _polynomial.Text(CrcCalculator.FormatHex(parameters.Polynomial, parameters.Width));
            _initial.Text(CrcCalculator.FormatHex(parameters.Initial, parameters.Width));
            _xorOut.Text(CrcCalculator.FormatHex(parameters.XorOut, parameters.Width));
            if (parameters.ReflectInput) _reflectInput.On(); else _reflectInput.Off();
            if (parameters.ReflectOutput) _reflectOutput.On(); else _reflectOutput.Off();
            _check.Text(CrcCalculator.FormatHex(preset.Check, parameters.Width));
        }
        finally { _applyingPreset = false; }
    }

    private void ParametersChanged()
    {
        if (_applyingPreset) return;
        _preset.Select(_preset.Items!.Single(item => Equals(item.Value, "custom")));
        _check.Text("");
        Invalidate();
    }

    private void Calculate()
    {
        Invalidate();
        double widthValue = _width.Value;
        if (widthValue != Math.Truncate(widthValue) || widthValue is < 1 or > 64) throw new ArgumentException(L("InvalidCrcParameters"));
        int width = (int)widthValue;
        var parameters = new CrcParameters(width, CrcCalculator.ParseHex(_polynomial.Text, width), CrcCalculator.ParseHex(_initial.Text, width),
            _reflectInput.IsOn, _reflectOutput.IsOn, CrcCalculator.ParseHex(_xorOut.Text, width));
        ulong result = CrcCalculator.Compute(BinaryText.Decode(_input.Text, (BinaryEncoding)_inputEncoding.SelectedItem!.Value!), parameters);
        _lastResult = (result, width);
        _output.Text(Format(result, width));
    }

    private string Format(ulong value, int width) => Selected(_outputFormat) switch
    {
        "hex" => CrcCalculator.FormatHex(value, width),
        "decimal" => value.ToString(CultureInfo.InvariantCulture),
        "binary" => new string(Enumerable.Range(0, width).Select(bit => ((value >> (width - bit - 1)) & 1) == 0 ? '0' : '1').ToArray()),
        "base64" => Convert.ToBase64String(Enumerable.Range(0, (width + 7) / 8).Select(i => (byte)(value >> (8 * (((width + 7) / 8) - i - 1)))).ToArray()),
        _ => throw new ArgumentException(L("InvalidEncoding"))
    };

    private void Invalidate() { _lastResult = null; _output.Text(""); Status.Hide(); }
    private static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
