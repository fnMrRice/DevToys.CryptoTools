namespace DevToys.CryptoTools.Cryptography;

internal sealed record SymmetricAlgorithm(string Algorithm, string Mode, int BlockSize);

internal static class SymmetricAlgorithmCatalog
{
    internal static readonly string[] Algorithms =
    [
        "AES", "SM4", "Camellia", "ARIA", "Twofish", "Serpent", "Blowfish", "CAST5", "DES", "TripleDES", "RC2",
        "ChaCha20", "XChaCha20", "Salsa20", "XSalsa20"
    ];

    internal static string[] Modes(string algorithm) => algorithm switch
    {
        "AES" or "SM4" or "Camellia" or "ARIA" or "Twofish" or "Serpent" => ["GCM", "CBC", "ECB", "CFB", "CFB8", "OFB", "CTR", "CCM", "EAX"],
        "Blowfish" or "CAST5" or "DES" or "TripleDES" or "RC2" => ["CBC", "ECB", "CFB", "CFB8", "OFB", "CTR", "EAX"],
        "ChaCha20" => ["Poly1305", "IETF"],
        "XChaCha20" => ["Poly1305", "Raw"],
        "Salsa20" or "XSalsa20" => ["Raw"],
        _ => throw new ArgumentException(L("InvalidAlgorithm"))
    };

    internal static SymmetricAlgorithm Resolve(string fullAlgorithm)
    {
        int separator = fullAlgorithm.LastIndexOf('-');
        if (separator <= 0) throw new ArgumentException(L("InvalidAlgorithm"));
        string algorithm = fullAlgorithm[..separator];
        string mode = fullAlgorithm[(separator + 1)..];
        if (!Modes(algorithm).Contains(mode)) throw new ArgumentException(L("InvalidAlgorithm"));
        int blockSize = algorithm switch
        {
            "AES" or "SM4" or "Camellia" or "ARIA" or "Twofish" or "Serpent" => 16,
            "Blowfish" or "CAST5" or "DES" or "TripleDES" or "RC2" => 8,
            _ => 0
        };
        return new(algorithm, mode, blockSize);
    }

    internal static string[] PaddingNames(string fullAlgorithm) => Resolve(fullAlgorithm).Mode is "ECB" or "CBC"
        ? ["PKCS7", "None", "Zeros", "ANSIX923", "ISO10126"] : ["None"];

    internal static int IvLength(string fullAlgorithm)
    {
        var algorithm = Resolve(fullAlgorithm);
        return algorithm.Mode switch
        {
            "ECB" => 0,
            "GCM" or "CCM" or "IETF" => 12,
            "Poly1305" => algorithm.Algorithm == "XChaCha20" ? 24 : 12,
            "Raw" => algorithm.Algorithm is "XChaCha20" or "XSalsa20" ? 24 : 8,
            _ => algorithm.BlockSize
        };
    }

    internal static int TagLength(string fullAlgorithm)
    {
        var algorithm = Resolve(fullAlgorithm);
        return algorithm.Mode switch { "GCM" or "CCM" or "Poly1305" => 16, "EAX" => algorithm.BlockSize, _ => 0 };
    }

    internal static int[] KeyLengths(string algorithm) => algorithm switch
    {
        "AES" or "Camellia" or "ARIA" or "Twofish" or "Serpent" => [16, 24, 32],
        "SM4" => [16],
        "Blowfish" => Enumerable.Range(4, 53).ToArray(),
        "CAST5" => Enumerable.Range(5, 12).ToArray(),
        "DES" => [8],
        "TripleDES" => [16, 24],
        "RC2" => Enumerable.Range(1, 128).ToArray(),
        "Salsa20" => [16, 32],
        "ChaCha20" or "XChaCha20" or "XSalsa20" => [32],
        _ => throw new ArgumentException(L("InvalidAlgorithm"))
    };

    internal static bool IsKeyLengthValid(string fullAlgorithm, int bytes) =>
        KeyLengths(Resolve(fullAlgorithm).Algorithm).Contains(bytes);

    internal static int DefaultKeyLength(string algorithm) => algorithm switch
    {
        "SM4" or "Blowfish" or "CAST5" or "RC2" => 16,
        "DES" => 8,
        "TripleDES" => 24,
        _ when Algorithms.Contains(algorithm) => 32,
        _ => throw new ArgumentException(L("InvalidAlgorithm"))
    };
}
