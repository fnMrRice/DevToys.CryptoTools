using System.ComponentModel.Composition;
using DevToys.Api;

namespace DevToys.CryptoTools;

[Export(typeof(GuiToolGroup))]
[Name(GroupName)]
internal sealed class CryptographyToolGroup : GuiToolGroup
{
    public const string GroupName = "DevToys.CryptoTools.Cryptography";

    public CryptographyToolGroup()
    {
        IconFontName = "FluentSystemIcons";
        IconGlyph = '\uE670';
        DisplayTitle = L("Cryptography");
        AccessibleName = DisplayTitle;
    }
}
