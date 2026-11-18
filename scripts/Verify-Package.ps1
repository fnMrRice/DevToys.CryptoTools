[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $PackagePath
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $PackagePath).Path)
try {
    $required = @(
        'DevToys.CryptoTools.nuspec',
        'README.md',
        'lib/net8.0/DevToys.CryptoTools.dll',
        'lib/net8.0/DevToys.CryptoTools.deps.json',
        'lib/net8.0/BouncyCastle.Cryptography.dll',
        'lib/net8.0/zh-Hans/DevToys.CryptoTools.resources.dll',
        'licenses/BouncyCastle.LICENSE.md'
    )
    foreach ($name in $required) {
        $entry = $archive.GetEntry($name)
        if ($null -eq $entry -or $entry.Length -eq 0) {
            throw "Missing or empty package entry: $name"
        }
    }
    if ($archive.Entries.FullName -match '(^|/)DevToys.Api.dll$') {
        throw 'The host API must not be bundled in the extension.'
    }
    $reader = [System.IO.StreamReader]::new($archive.GetEntry('DevToys.CryptoTools.nuspec').Open())
    try { [xml] $manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($manifest.SelectNodes('//*[local-name()="dependency"]').Count -ne 0) {
        throw 'The installation package must bundle its dependencies.'
    }
    Write-Output "Package verified: $PackagePath"
}
finally {
    $archive.Dispose()
}
