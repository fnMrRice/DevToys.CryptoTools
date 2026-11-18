using DevToys.Api;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal static class PlaceholderTextInput
{
    // DevToys.Api 2.0.10 does not expose TextBox.Placeholder. Keep the native
    // editable value and command bar intact, and render a separate ghost label
    // over the text area. DevToys layout containers and TextBlock inherit
    // pointer-events:none, so the overlay does not intercept input or clicks.
    internal static IUIGrid Wrap(IUISingleLineTextInput input, string placeholder, string? id = null)
    {
        var hint = Label(id is null ? null : id + "-hint")
            .Text(placeholder)
            .Style(UILabelStyle.Body)
            .NeverWrap()
            .Disable();
        var textArea = Grid().Rows(Fraction(1), Auto, Fraction(1))
            .Columns(new UIGridLength(10), Fraction(1), new UIGridLength(10))
            .RowNoSpacing().ColumnNoSpacing().Disable()
            .Cells(At(1, 1, hint));
        var overlay = Grid(id is null ? null : id + "-overlay")
            .Rows(Fraction(1), new UIGridLength(32))
            .RowNoSpacing().ColumnNoSpacing().Disable()
            .Cells(At(1, 0, textArea));
        var view = Grid(id).RowNoSpacing().ColumnNoSpacing()
            .Cells(At(0, 0, input), At(0, 0, overlay));

        void Refresh()
        {
            if (input.IsVisible && input.IsEnabled && string.IsNullOrEmpty(input.Text)) overlay.Show();
            else overlay.Hide();
        }
        input.TextChanged += (_, _) => Refresh();
        input.IsEnabledChanged += (_, _) => Refresh();
        input.IsVisibleChanged += (_, _) => Refresh();
        Refresh();
        return view;
    }

    private static IUIGridCell At(int row, int column, IUIElement child) =>
        Cell().Row(row).Column(column).WithChild(child);
}
