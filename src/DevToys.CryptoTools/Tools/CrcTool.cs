using System.ComponentModel.Composition;
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
internal sealed class CrcTool : CryptoToolBase, IDisposable
{
    private readonly IUISelectDropDownList _preset = SelectDropDownList("crc-preset")
        .WithItems([.. CrcCalculator.Presets.Select(p => Item(p.Name, p.Name)), Item(L("CrcCustom"), "custom")]).Select(0);
    private readonly IUINumberInput _width = NumberInput("crc-width", 1, 64, 1).Value(32).HideCommandBar();
    private readonly IUISingleLineTextInput _polynomial = SingleLineTextInput("crc-polynomial").HideCommandBar();
    private readonly IUISingleLineTextInput _initial = SingleLineTextInput("crc-initial").HideCommandBar();
    private readonly IUISingleLineTextInput _xorOut = SingleLineTextInput("crc-xor-out").HideCommandBar();
    private readonly IUISwitch _reflectInput = Switch("crc-ref-in").OnText(L("CertEnabled")).OffText(L("CertDisabled"));
    private readonly IUISwitch _reflectOutput = Switch("crc-ref-out").OnText(L("CertEnabled")).OffText(L("CertDisabled"));
    private readonly IUISingleLineTextInput _check = SingleLineTextInput("crc-check").ReadOnly().HideCommandBar();
    private readonly IUISelectDropDownList _inputEncoding = SelectDropDownList("crc-input-encoding")
        .WithItems(Item(L("Utf8Text"), BinaryEncoding.Text), Item("Hex", BinaryEncoding.Hex), Item("Base64", BinaryEncoding.Base64)).Select(0);
    private readonly IUIMultiLineTextInput _input = MultiLineTextInput("crc-input").Title(L("Input")).Text("123456789").ShowCommandBar();
    private readonly IUIFileSelector _fileSelector = FileSelector("crc-input-file").CanSelectOneFile();
    private readonly IUIButton _clearFile = Button("crc-clear-file").Text(L("CrcClearFile")).Hide();
    private readonly IUISingleLineTextInput _output = SingleLineTextInput("crc-output").Title(L("CrcOutputHex")).ReadOnly().ShowCommandBar();
    private readonly IUISingleLineTextInput _expected = SingleLineTextInput("crc-expected").Title(L("CrcExpected")).ShowCommandBar();
    private readonly IUIInfoBar _verification = InfoBar("crc-verification").Title(L("CrcVerification")).Hide();
    private readonly IUIStack _layout;
    private bool _applyingPreset;
    private bool _selectingFile;
    private bool _synchronizingFiles;
    private bool _ready;
    private SandboxedFileReader? _file;
    private CancellationTokenSource? _calculation;
    private int _revision;
    private (ulong Value, int Width)? _result;
    internal Task CalculationTask { get; private set; } = Task.CompletedTask;

    protected override IUIElement BuildLayout() => _layout;

    public CrcTool()
    {
        _input.CommandBarExtraContent(Stack().Horizontal().SmallSpacing().WithChildren(_inputEncoding, _clearFile));
        _fileSelector.OnFilesSelected(files =>
        {
            if (!_synchronizingFiles)
            {
                try { SelectFile(files); }
                catch (ArgumentException ex) { Status.Description(ex.Message).Error().Show(); }
            }
            return ValueTask.CompletedTask;
        });
        _clearFile.OnClick(() => SelectFile([]));
        _preset.OnItemSelected(_ => ApplyPreset());
        foreach (var field in new[] { _polynomial, _initial, _xorOut }) field.TextChanged += (_, _) => ParametersChanged();
        _width.ValueChanged += (_, _) => ParametersChanged();
        _reflectInput.IsOnChanged += (_, _) => ParametersChanged();
        _reflectOutput.IsOnChanged += (_, _) => ParametersChanged();
        _input.TextChanged += (_, _) =>
        {
            if (_selectingFile) return;
            Invalidate();
            ClearFile();
            RequestCalculation();
        };
        _inputEncoding.OnItemSelected(_ => { if (_file is null) RequestCalculation(); });
        _expected.TextChanged += (_, _) => Verify();
        var parameters = SettingGroup("crc-parameters").Title(L("CrcPreset")).Description(L("CrcPresetDescription"))
            .Icon("FluentSystemIcons", '\uE670').InteractiveElement(_preset)
            .WithSettings(
                Parameter("width", "CrcWidth", "CrcWidthDescription", _width),
                Parameter("polynomial", "CrcPolynomial", "CrcPolynomialHint", _polynomial),
                Parameter("initial", "CrcInitial", "CrcInitialDescription", _initial),
                Parameter("xor-out", "CrcXorOut", "CrcXorOutDescription", _xorOut),
                Parameter("ref-in", "CrcReflectInput", "CrcReflectInputDescription", _reflectInput),
                Parameter("ref-out", "CrcReflectOutput", "CrcReflectOutputDescription", _reflectOutput),
                Parameter("check", "CrcCheck", "CrcCheckDescription", _check));
        var configuration = Stack("crc-configuration").Vertical().SmallSpacing().AlignVertically(UIVerticalAlignment.Top).WithChildren(
            Label().Text(L("CrcConfiguration")).Style(UILabelStyle.BodyStrong).AlignHorizontally(UIHorizontalAlignment.Left),
            parameters);
        var inputs = Grid("crc-inputs").Rows(Fraction(1)).Columns(Fraction(1), Auto, Fraction(1))
            .ColumnMediumSpacing().AlignVertically(UIVerticalAlignment.Top).Cells(
                At(0, 0, _input), At(0, 1, Label().Text(L("CrcOr")).AlignVertically(UIVerticalAlignment.Center)), At(0, 2, _fileSelector));
        var results = Stack("crc-results").Vertical().SmallSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(_output, _expected, _verification);
        // A stretched Grid inherits the page height and distributes spare height
        // among Auto rows. Keep these sections in natural flow, as the host hash tool does.
        _layout = Stack("crc-layout").Vertical().LargeSpacing().AlignVertically(UIVerticalAlignment.Top)
            .WithChildren(configuration, inputs, results, Status);
        var defaultPreset = _preset.Items!.First(item => Equals(item.Value, "CRC-32/ISO-HDLC"));
        _preset.Select(defaultPreset);
        ApplyPreset();
        _ready = true;
        RequestCalculation();
    }

    private void ApplyPreset()
    {
        if (_applyingPreset) return;
        Invalidate();
        var preset = CrcCalculator.Presets.FirstOrDefault(p => p.Name == Selected(_preset));
        if (preset is null) { _check.Text(""); RequestCalculation(); return; }
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
        RequestCalculation();
    }

    private void ParametersChanged()
    {
        if (_applyingPreset) return;
        _applyingPreset = true;
        try { _preset.Select(_preset.Items!.Single(item => Equals(item.Value, "custom"))); }
        finally { _applyingPreset = false; }
        _check.Text("");
        RequestCalculation();
    }

    private void RequestCalculation()
    {
        if (_ready) CalculationTask = CalculateAsync().AsTask();
    }

    private async ValueTask CalculateAsync()
    {
        Invalidate();
        int revision = _revision;
        using var cancellation = new CancellationTokenSource();
        _calculation = cancellation;
        try
        {
            double widthValue = _width.Value;
            if (widthValue != Math.Truncate(widthValue) || widthValue is < 1 or > 64) throw new ArgumentException(L("InvalidCrcParameters"));
            int width = (int)widthValue;
            var parameters = new CrcParameters(width, CrcCalculator.ParseHex(_polynomial.Text, width), CrcCalculator.ParseHex(_initial.Text, width),
                _reflectInput.IsOn, _reflectOutput.IsOn, CrcCalculator.ParseHex(_xorOut.Text, width));
            ulong value;
            if (_file is { } file)
            {
                using var stream = await file.GetNewAccessToFileContentAsync(cancellation.Token);
                value = await Task.Run(async () => await CrcCalculator.ComputeAsync(stream, parameters, cancellation.Token), cancellation.Token);
            }
            else value = CrcCalculator.Compute(BinaryText.Decode(_input.Text, (BinaryEncoding)_inputEncoding.SelectedItem!.Value!), parameters);
            if (revision != _revision) return;
            _result = (value, width);
            _output.Text(CrcCalculator.FormatHex(value, width));
            Verify();
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidOperationException or NotSupportedException or IOException or UnauthorizedAccessException)
        {
            if (revision == _revision) Status.Description(ex.Message).Error().Show();
        }
        finally
        {
            if (ReferenceEquals(_calculation, cancellation)) _calculation = null;
        }
    }

    private void SelectFile(SandboxedFileReader[] files)
    {
        Invalidate();
        if (files.Length > 1)
        {
            ClearFile();
            foreach (var rejected in files) rejected.Dispose();
            throw new ArgumentException(L("SelectOneFile"));
        }
        if (files.Length == 0) { ClearFile(); RequestCalculation(); return; }
        if (!ReferenceEquals(_file, files[0])) ClearFile();
        _file = files[0];
        SynchronizeFiles([_file]);
        _clearFile.Show();
        _selectingFile = true;
        try { _input.Text(""); }
        finally { _selectingFile = false; }
        RequestCalculation();
    }

    private void ClearFile()
    {
        _file?.Dispose();
        _file = null;
        SynchronizeFiles([]);
        _clearFile.Hide();
    }

    private void SynchronizeFiles(SandboxedFileReader[] files)
    {
        _synchronizingFiles = true;
        try { _fileSelector.WithFiles(files); }
        finally { _synchronizingFiles = false; }
    }

    private void Verify()
    {
        _verification.Hide();
        if (_result is not { } result || string.IsNullOrWhiteSpace(_expected.Text)) return;
        try
        {
            bool matches = CrcCalculator.ParseHex(_expected.Text, result.Width) == result.Value;
            _verification.Description(L(matches ? "CrcMatches" : "CrcDoesNotMatch"));
            if (matches) _verification.Success().Show(); else _verification.Error().Show();
        }
        catch (ArgumentException) { _verification.Description(L("InvalidCrcHex")).Error().Show(); }
    }

    private void Invalidate()
    {
        _revision++;
        _calculation?.Cancel();
        _result = null;
        _output.Text("");
        _verification.Hide();
        Status.Hide();
    }

    public void Dispose()
    {
        _ready = false;
        _revision++;
        _calculation?.Cancel();
        _file?.Dispose();
        _file = null;
    }

    private static IUISetting Parameter(string id, string title, string description, IUIElement input) =>
        Setting("crc-" + id + "-setting").Title(L(title)).Description(L(description))
            .Icon("FluentSystemIcons", '\uF57D').InteractiveElement(input);
    private static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
