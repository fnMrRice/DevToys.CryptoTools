using System.Globalization;
using DevToys.Api;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal static class KeyPairExportDialog
{
    internal static async ValueTask ShowAsync(UIToolView view, IFileStorage storage,
        ReadOnlyMemory<byte> privateBytes, ReadOnlyMemory<byte> publicBytes)
    {
        string? directory = null;
        bool busy = false;
        var fileName = SingleLineTextInput("key-export-name").Title(L("KeyExportName")).Text("keypair").HideCommandBar();
        var preview = Label("key-export-preview").Style(UILabelStyle.Caption).AlignHorizontally(UIHorizontalAlignment.Left);
        var error = InfoBar("key-export-error").Title(L("Status")).Hide();
        var browse = Button("key-export-browse").Text(L("KeyExportChooseFolder"));
        var folder = Setting("key-export-directory").Title(L("KeyExportDirectory"))
            .Description(L("KeyExportChooseFolder")).InteractiveElement(browse);
        var save = Button("key-export-save").Text(L("KeyExportSave")).AccentAppearance();
        var cancel = Button("key-export-cancel").Text(L("KeyExportCancel"));

        void RefreshPreview() => preview.Text(string.Format(CultureInfo.CurrentUICulture,
            L("KeyExportFilePreview"), fileName.Text + ".key", fileName.Text + ".pub"));
        void SetBusy(bool value)
        {
            busy = value;
            foreach (var control in new IUIElement[] { fileName, browse, save, cancel })
                if (value) control.Disable(); else control.Enable();
        }
        void ShowError(Exception exception) => error.Description(exception.Message).Error().Show();

        async ValueTask BrowseAsync()
        {
            if (busy) return;
            SetBusy(true);
            error.Hide();
            try
            {
                string? selected = await storage.PickFolderAsync();
                if (!string.IsNullOrWhiteSpace(selected))
                {
                    directory = selected;
                    folder.Description(selected);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException)
            {
                ShowError(exception);
            }
            finally { SetBusy(false); }
        }

        async ValueTask SaveAsync()
        {
            if (busy) return;
            SetBusy(true);
            error.Hide();
            try
            {
                await KeyPairFileExport.ExportAsync(directory ?? "", fileName.Text, privateBytes, publicBytes);
                view.CurrentOpenedDialog?.Close();
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException)
            {
                ShowError(exception);
            }
            finally { SetBusy(false); }
        }

        fileName.TextChanged += (_, _) => { error.Hide(); RefreshPreview(); };
        browse.OnClick(BrowseAsync);
        save.OnClick(SaveAsync);
        cancel.OnClick(() => { if (!busy) view.CurrentOpenedDialog?.Close(); });
        RefreshPreview();
        var content = Stack("key-export-dialog").Vertical().MediumSpacing().AlignVertically(UIVerticalAlignment.Top).WithChildren(
            Label().Text(L("KeyExport")).Style(UILabelStyle.Subtitle).AlignHorizontally(UIHorizontalAlignment.Left),
            fileName, preview, folder, error);
        var footer = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Right).WithChildren(cancel, save);
        using UIDialog dialog = await view.OpenDialogAsync(content, footer, isDismissible: false);
        await dialog.DialogCloseAwaiter;
    }
}
