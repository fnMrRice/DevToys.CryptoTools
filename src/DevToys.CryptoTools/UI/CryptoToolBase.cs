using System.Security.Cryptography;
using DevToys.Api;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal abstract class CryptoToolBase : IGuiTool
{
    private readonly List<IUIElement> _elements = [];
    protected IUIInfoBar Status { get; } = InfoBar().Title(L("Status")).Hide();
    private UIToolView? _view;

    protected virtual bool IsScrollable => true;
    protected virtual IUIElement BuildLayout() => Stack().Vertical().MediumSpacing().WithChildren([.. _elements, Status]);
    public UIToolView View => _view ??= new(IsScrollable, BuildLayout());

    protected T Add<T>(T element) where T : IUIElement
    {
        _elements.Add(element);
        return element;
    }

    protected void Note(string text) => Add(Label().Text(text));
    protected IUISingleLineTextInput Input(string title, string initial = "") => Add(SingleLineTextInput().Title(title).Text(initial));
    protected IUIMultiLineTextInput Editor(string title, bool readOnly = false)
    {
        var editor = MultiLineTextInput().Title(title);
        if (readOnly) editor.ReadOnly();
        return Add(editor);
    }

    protected IUISelectDropDownList Choice(string title, params string[] values) =>
        Add(SelectDropDownList().Title(title).WithItems(values.Select(v => Item(v, v)).ToArray()).Select(0));

    protected static string Selected(IUISelectDropDownList choice) => (string)choice.SelectedItem!.Value!;

    protected void ActionButton(string text, Action action) => Add(CreateActionButton(text, action));

    protected IUIButton CreateActionButton(string text, Action action, string? id = null) =>
        Button(id).Text(text).OnClick(() => Execute(action));

    protected void Execute(Action action)
    {
        Status.Hide();
        try
        {
            action();
            Status.Description(L("Completed")).Success().Show();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or InvalidOperationException or NotSupportedException or System.Text.Json.JsonException or Org.BouncyCastle.Crypto.CryptoException or System.IO.IOException)
        {
            Status.Description(ex.Message).Error().Show();
        }
    }

    protected async ValueTask ExecuteAsync(Func<ValueTask> action)
    {
        Status.Hide();
        try
        {
            await action();
            Status.Description(L("Completed")).Success().Show();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or InvalidOperationException or NotSupportedException or System.Text.Json.JsonException or Org.BouncyCastle.Crypto.CryptoException or IOException or UnauthorizedAccessException)
        {
            Status.Description(ex.Message).Error().Show();
        }
    }

    public virtual void OnDataReceived(string dataTypeName, object? parsedData) { }
}
