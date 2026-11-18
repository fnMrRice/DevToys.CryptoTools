using DevToys.Api;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class PlaceholderTextInputTests
{
    [Fact]
    public void PlaceholderNeverBecomesInputDataAndTracksTextClearing()
    {
        var input = SingleLineTextInput("placeholder-input").ShowCommandBar();
        var view = PlaceholderTextInput.Wrap(input, "Generated automatically when empty", "placeholder");
        var overlay = Assert.IsAssignableFrom<IUIGrid>(view.GetChildElementById("placeholder-overlay"));
        var hint = Assert.IsAssignableFrom<IUILabel>(view.GetChildElementById("placeholder-hint"));
        Assert.Empty(input.Text);
        Assert.False(input.HideCommandBar);
        Assert.True(overlay.IsVisible);
        Assert.False(overlay.IsEnabled);
        Assert.False(hint.IsEnabled);

        input.Text("00112233");
        Assert.Equal("00112233", input.Text);
        Assert.False(overlay.IsVisible);
        input.Text("");
        Assert.Empty(input.Text);
        Assert.True(overlay.IsVisible);
    }

    [Fact]
    public void PlaceholderIsHiddenWhenInputIsDisabledOrHidden()
    {
        var input = SingleLineTextInput();
        var view = PlaceholderTextInput.Wrap(input, "Hint", "placeholder");
        var overlay = Assert.IsAssignableFrom<IUIGrid>(view.GetChildElementById("placeholder-overlay"));
        input.Disable();
        Assert.False(overlay.IsVisible);
        input.Enable();
        Assert.True(overlay.IsVisible);
        input.Hide();
        Assert.False(overlay.IsVisible);
        input.Show();
        Assert.True(overlay.IsVisible);
    }
}
