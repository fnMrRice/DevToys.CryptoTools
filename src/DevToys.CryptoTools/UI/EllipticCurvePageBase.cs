using DevToys.Api;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal abstract class EllipticCurvePageBase : CryptoToolBase
{
    protected IUISelectDropDownList Algorithm { get; }
    protected KeyFileInput KeyInput { get; }
    protected IUIMultiLineTextInput InputText { get; }
    protected IUIMultiLineTextInput OutputText { get; }
    private IUIElement? _layout;

    protected EllipticCurvePageBase(string prefix, string[] algorithms)
    {
        Algorithm = SelectDropDownList(prefix + "-algorithm").Title(L("Algorithm"))
            .WithItems(algorithms.Select(a => Item(a, a)).ToArray()).Select(0).AlignHorizontally(UIHorizontalAlignment.Left);
        InputText = MultiLineTextInput(prefix + "-input").Title(L("Input")).ShowCommandBar().Extendable();
        OutputText = MultiLineTextInput(prefix + "-output").Title(L("Output")).ReadOnly().ShowCommandBar().Extendable();
        KeyInput = new KeyFileInput(prefix + "-key", ExecuteAsync, () => OutputText.Text(""));
    }

    protected override bool IsScrollable => false;
    protected override IUIElement BuildLayout() => _layout ?? throw new InvalidOperationException();

    protected void SetLayout(string prefix, IUIElement options, IUIElement keyPanel, IUIElement inputPane, params IUIElement[] actions)
    {
        var configuration = Grid(prefix + "-configuration").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(
            At(0, 0, options.AlignVertically(UIVerticalAlignment.Top)), At(0, 1, keyPanel));
        var editors = SplitGrid(prefix + "-editors").Vertical().WithLeftPaneChild(inputPane).WithRightPaneChild(OutputText);
        _layout = Grid(prefix + "-layout").Rows(Auto, Auto, Fraction(1), Auto).RowMediumSpacing().Cells(
            At(0, 0, configuration),
            At(1, 0, Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(actions)),
            At(2, 0, editors), At(3, 0, Status));
    }

    protected void ShowResult(Func<string> action) { OutputText.Text(""); OutputText.Text(action()); }
    protected static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
