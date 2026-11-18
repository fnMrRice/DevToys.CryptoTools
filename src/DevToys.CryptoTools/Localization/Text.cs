using System.Globalization;
using System.Resources;

namespace DevToys.CryptoTools.Localization;

internal static class Text
{
    internal const string ResourceBaseName = "DevToys.CryptoTools.Localization.Strings";
    internal static readonly ResourceManager Resources = new(ResourceBaseName, typeof(Text).Assembly);
    internal static string L(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new InvalidOperationException($"Missing resource: {key}");
}
