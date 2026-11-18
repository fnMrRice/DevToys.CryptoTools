using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevToys.CryptoTools.Cryptography;

internal static class EcDomains
{
    internal static readonly string[] Curves = ["P256", "P384", "P521", "secp256k1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"];

    internal static bool SupportsCoordinates(string algorithm) => CurveName(algorithm) is not null;

    internal static ECNamedDomainParameters ForAlgorithm(string algorithm)
    {
        string name = CurveName(algorithm) ?? throw new ArgumentException(L("InvalidAlgorithm"));
        var oid = ECNamedCurveTable.GetOid(name);
        var curve = ECNamedCurveTable.GetByOid(oid);
        return new ECNamedDomainParameters(oid, curve);
    }

    private static string? CurveName(string algorithm)
    {
        if (algorithm is "SM2" or "SM2-C1C3C2" or "SM2-C1C2C3") return "sm2p256v1";
        if (!(algorithm.StartsWith("ECDSA-", StringComparison.Ordinal) || algorithm.StartsWith("ECDH-", StringComparison.Ordinal))) return null;
        string curve = algorithm[(algorithm.IndexOf('-') + 1)..];
        return curve switch
        {
            "P256" => "secp256r1",
            "P384" => "secp384r1",
            "P521" => "secp521r1",
            "secp256k1" or "brainpoolP256r1" or "brainpoolP384r1" or "brainpoolP512r1" => curve,
            _ => null
        };
    }
}
