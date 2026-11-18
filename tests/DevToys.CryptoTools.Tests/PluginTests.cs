using System.Collections;
using System.ComponentModel.Composition.Hosting;
using System.Globalization;
using System.Reflection;
using DevToys.Api;
using DevToys.CryptoTools.Localization;
using DevToys.CryptoTools.Tools;

namespace DevToys.CryptoTools.Tests;

public class PluginTests
{
    [Fact]
    public void MefDiscoversFiveToolsInTheRequestedGroups()
    {
        using var catalog = new AssemblyCatalog(typeof(KeyGeneratorTool).Assembly);
        using var container = new CompositionContainer(catalog);
        var tools = container.GetExportedValues<IGuiTool>().ToArray();
        Assert.Equal(5, tools.Length);
        Assert.Single(container.GetExportedValues<IResourceAssemblyIdentifier>());
        Assert.Single(container.GetExportedValues<GuiToolGroup>());
        foreach (var tool in tools)
        {
            Assert.Same(tool.View, tool.View);
            var root = Assert.IsAssignableFrom<IUIStack>(tool.View.RootElement);
            Assert.NotNull(root.Children);
            Assert.NotEmpty(root.Children);
            var metadata = tool.GetType().GetCustomAttribute<ToolDisplayInformationAttribute>()!;
            string expected = tool is KeyGeneratorTool or CertificateGeneratorTool
                ? PredefinedCommonToolGroupNames.Generators : CryptographyToolGroup.GroupName;
            Assert.Equal(expected, metadata.GroupName);
            Assert.Equal(Text.ResourceBaseName, metadata.ResourceManagerBaseName);
            Assert.NotNull(Text.Resources.GetString(metadata.ShortDisplayTitleResourceName, CultureInfo.InvariantCulture));
            Assert.NotNull(Text.Resources.GetString(metadata.DescriptionResourceName, CultureInfo.InvariantCulture));
        }
    }

    [Fact]
    public void ChineseResourcesAreCompleteAndUnsupportedLanguagesFallBackToEnglish()
    {
        var english = Text.Resources.GetResourceSet(CultureInfo.InvariantCulture, true, true)!;
        var chinese = Text.Resources.GetResourceSet(CultureInfo.GetCultureInfo("zh-Hans"), true, false)!;
        foreach (DictionaryEntry entry in english)
        {
            string key = (string)entry.Key;
            Assert.False(string.IsNullOrWhiteSpace(chinese.GetString(key)));
            Assert.Equal(entry.Value, Text.Resources.GetString(key, CultureInfo.GetCultureInfo("fr-FR")));
        }
        Assert.Equal("Key generator", Text.Resources.GetString("KeyTitle", CultureInfo.GetCultureInfo("en-US")));
        Assert.Equal("密钥生成", Text.Resources.GetString("KeyTitle", CultureInfo.GetCultureInfo("zh-CN")));
    }

    [Fact]
    public async Task InvalidUserInputIsShownInTheToolWithoutEscapingTheButtonHandler()
    {
        var tool = new RsaTool();
        var root = (IUIStack)tool.View.RootElement!;
        Assert.NotNull(root.Children);
        var encrypt = root.Children.OfType<IUIButton>().First();
        await encrypt.OnClickAction!();
        Assert.True(root.Children.OfType<IUIInfoBar>().Single().IsVisible);
        Assert.Empty(root.Children.OfType<IUIMultiLineTextInput>().Last().Text ?? "");
    }
}
