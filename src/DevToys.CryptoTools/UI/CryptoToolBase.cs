using System.Security.Cryptography;
using DevToys.Api;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal abstract class CryptoToolBase : IGuiTool
{
    private readonly List<IUIElement> _elements = [];
    private readonly IUIInfoBar _status = InfoBar().Title(L("Status")).Hide();
    private UIToolView? _view;

    public UIToolView View => _view ??= new(Stack().Vertical().MediumSpacing().WithChildren([.. _elements, _status]));

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

    protected void ActionButton(string text, Action action) => Add(Button().Text(text).OnClick(() =>
    {
        _status.Hide();
        try
        {
            action();
            _status.Description(L("Completed")).Success().Show();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or InvalidOperationException or NotSupportedException or System.Text.Json.JsonException)
        {
            _status.Description(ex.Message).Error().Show();
        }
    }));

    public void OnDataReceived(string dataTypeName, object? parsedData) { }
}
