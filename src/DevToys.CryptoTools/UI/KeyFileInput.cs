using System.Security.Cryptography;
using System.Text;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal sealed class KeyFileInput
{
    internal IUIMultiLineTextInput Editor { get; }
    internal IUIElement View { get; }
    internal IUIFileSelector Selector { get; }
    private readonly Action? _onImported;

    internal KeyFileInput(string id, Func<Func<ValueTask>, ValueTask> execute, Action? onImported = null)
    {
        _onImported = onImported;
        Editor = MultiLineTextInput(id + "-pem").Title(L("KeyOrCertificate")).ShowCommandBar().CanCopyWhenEditable().Extendable();
        Selector = FileSelector(id + "-file").CanSelectOneFile().LimitFileTypesTo("pem", "key", "der", "cer", "crt", "pub")
            .OnFilesSelected(files => files.Length == 0 ? ValueTask.CompletedTask : execute(() => ImportAsync(files)));
        View = Grid(id).Rows(Auto, Auto, new UIGridLength(125)).RowSmallSpacing().Cells(
            At(0, Label().Text(L("KeyImportHint")).AlignHorizontally(UIHorizontalAlignment.Left)),
            At(1, Selector), At(2, Editor));
    }

    internal string GetPem()
    {
        byte[] data = Encoding.UTF8.GetBytes(Editor.Text);
        try { return EllipticCurveKeyImport.Import(data); }
        finally { CryptographicOperations.ZeroMemory(data); }
    }
    internal void Clear() { Editor.Text(""); Selector.WithFiles([]); }

    private async ValueTask ImportAsync(SandboxedFileReader[] files)
    {
        Editor.Text("");
        _onImported?.Invoke();
        byte[] data = await FileImport.ReadAsync(files);
        try { Editor.Text(EllipticCurveKeyImport.Import(data)); }
        finally { CryptographicOperations.ZeroMemory(data); Selector.WithFiles([]); }
    }

    private static IUIGridCell At(int row, IUIElement child) => Cell().Row(row).Column(0).WithChild(child);
}
