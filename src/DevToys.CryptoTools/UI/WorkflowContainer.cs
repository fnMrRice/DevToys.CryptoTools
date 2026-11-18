using DevToys.Api;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

// The public SDK has no sidebar navigation service. Reuse the destination's actual
// form inside the current tool so a handoff never requires a clipboard round trip.
internal sealed class WorkflowContainer
{
    private readonly IUIElement _initial;
    internal IUIGrid Root { get; } = Grid().Rows(Auto, Fraction(1)).RowMediumSpacing();

    internal WorkflowContainer(IUIElement initial)
    {
        _initial = initial;
        Restore();
    }

    internal void Open(string title, CryptoToolBase destination, string dataTypeName, object draft)
    {
        destination.OnDataReceived(dataTypeName, draft);
        Root.Cells(
            At(0, Stack().Horizontal().MediumSpacing().WithChildren(
                Button().Text(L("Back")).OnClick(Restore), Label().Text(title).Style(UILabelStyle.BodyStrong))),
            At(1, destination.View.RootElement!));
    }

    private void Restore() => Root.Cells(At(1, _initial));
    private static IUIGridCell At(int row, IUIElement child) => Cell().Row(row).Column(0).WithChild(child);
}
