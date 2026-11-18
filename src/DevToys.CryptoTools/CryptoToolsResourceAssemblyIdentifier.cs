using System.ComponentModel.Composition;
using DevToys.Api;

namespace DevToys.CryptoTools;

[Export(typeof(IResourceAssemblyIdentifier))]
[Name(nameof(CryptoToolsResourceAssemblyIdentifier))]
internal sealed class CryptoToolsResourceAssemblyIdentifier : IResourceAssemblyIdentifier
{
    public ValueTask<FontDefinition[]> GetFontDefinitionsAsync() => ValueTask.FromResult(Array.Empty<FontDefinition>());
}
