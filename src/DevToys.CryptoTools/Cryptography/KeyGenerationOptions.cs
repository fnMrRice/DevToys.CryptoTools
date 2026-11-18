using System.Globalization;

namespace DevToys.CryptoTools.Cryptography;

internal static class KeyGenerationOptions
{
    internal static readonly string[] Families = ["RSA", "ECDSA", "ECDH", "Ed25519", "Ed448", "X25519", "X448", "SM2"];
    internal static readonly int[] RsaKeySizes = [2048, 3072, 4096];
    internal static readonly string[] Curves =
    [
        "P256", "P384", "P521", "secp256k1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"
    ];

    internal static string Resolve(string family, int rsaKeySize, string curve)
    {
        if (family == "RSA")
        {
            if (!RsaKeySizes.Contains(rsaKeySize)) throw new ArgumentException(L("InvalidAlgorithm"));
            return "RSA-" + rsaKeySize.ToString(CultureInfo.InvariantCulture);
        }
        if (family is "ECDSA" or "ECDH")
        {
            if (!Curves.Contains(curve)) throw new ArgumentException(L("InvalidAlgorithm"));
            return family + "-" + curve;
        }
        if (Families.Contains(family)) return family;
        throw new ArgumentException(L("InvalidAlgorithm"));
    }
}
