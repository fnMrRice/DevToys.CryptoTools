using DevToys.CryptoTools;

namespace DevToys.CryptoTools.Tests;

public class InfrastructureTests
{
    [Fact]
    public async Task ResourceIdentifierDoesNotRequireCustomFonts()
    {
        Assert.Empty(await new CryptoToolsResourceAssemblyIdentifier().GetFontDefinitionsAsync());
    }

    [Fact]
    public void CryptographyGroupHasRequestedTitle()
    {
        Assert.False(string.IsNullOrWhiteSpace(new CryptographyToolGroup().DisplayTitle));
    }
}
