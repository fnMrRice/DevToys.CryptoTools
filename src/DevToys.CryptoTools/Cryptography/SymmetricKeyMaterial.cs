namespace DevToys.CryptoTools.Cryptography;

internal static class SymmetricKeyMaterial
{
    // Key normalization is independent of message padding. Keep the original
    // decoded bytes unchanged, zero-fill at the right, or discard the tail.
    internal static byte[] Normalize(string algorithm, byte[] input, int selectedBytes)
    {
        if (!SymmetricAlgorithmCatalog.KeyLengths(algorithm).Contains(selectedBytes))
            throw new ArgumentException(L("InvalidKeySize"));
        ArgumentNullException.ThrowIfNull(input);
        byte[] normalized = new byte[selectedBytes];
        input.AsSpan(0, Math.Min(input.Length, selectedBytes)).CopyTo(normalized);
        return normalized;
    }
}
