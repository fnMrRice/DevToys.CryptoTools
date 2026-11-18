using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record KeyMaterial(string PublicKey = "", string PrivateKey = "", string SymmetricKey = "");

internal static class KeyGenerator
{
    internal static readonly string[] Algorithms =
    [
        "RSA-2048", "RSA-3072", "RSA-4096",
        "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "ECDSA-secp256k1", "ECDSA-brainpoolP256r1", "ECDSA-brainpoolP384r1", "ECDSA-brainpoolP512r1",
        "ECDH-P256", "ECDH-P384", "ECDH-P521", "ECDH-secp256k1", "ECDH-brainpoolP256r1", "ECDH-brainpoolP384r1", "ECDH-brainpoolP512r1",
        "Ed25519", "Ed448", "X25519", "X448", "SM2",
        "AES-128", "AES-192", "AES-256", "ChaCha20-256", "SM4-128"
    ];

    internal static KeyMaterial Generate(string algorithm)
    {
        if (!Algorithms.Contains(algorithm)) throw new ArgumentException(L("InvalidAlgorithm"));
        if (algorithm.StartsWith("RSA-", StringComparison.Ordinal))
        {
            using var rsa = RSA.Create(int.Parse(algorithm[4..], System.Globalization.CultureInfo.InvariantCulture));
            return new(rsa.ExportSubjectPublicKeyInfoPem(), rsa.ExportPkcs8PrivateKeyPem());
        }
        if (algorithm.StartsWith("ECDSA-", StringComparison.Ordinal) || algorithm.StartsWith("ECDH-", StringComparison.Ordinal))
            return Export(GenerateEc(algorithm));
        if (algorithm == "SM2") return Export(GenerateSm2());
        if (algorithm is "Ed25519" or "Ed448" or "X25519" or "X448")
            return Export(GenerateModernCurve(algorithm));

        int bytes = algorithm switch { "AES-128" or "SM4-128" => 16, "AES-192" => 24, _ => 32 };
        return new(SymmetricKey: Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)));
    }

    internal static AsymmetricCipherKeyPair GenerateModernCurve(string algorithm)
    {
        var random = new SecureRandom();
        return algorithm switch
        {
            "Ed25519" => Pair(new Ed25519PrivateKeyParameters(random)),
            "Ed448" => Pair(new Ed448PrivateKeyParameters(random)),
            "X25519" => Pair(new X25519PrivateKeyParameters(random)),
            "X448" => Pair(new X448PrivateKeyParameters(random)),
            _ => throw new ArgumentException(L("InvalidAlgorithm"))
        };
    }

    internal static AsymmetricCipherKeyPair GenerateSm2() => GenerateEc("SM2");

    private static AsymmetricCipherKeyPair GenerateEc(string algorithm)
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(EcDomains.ForAlgorithm(algorithm), new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair Pair(Ed25519PrivateKeyParameters key) => new(key.GeneratePublicKey(), key);
    private static AsymmetricCipherKeyPair Pair(Ed448PrivateKeyParameters key) => new(key.GeneratePublicKey(), key);
    private static AsymmetricCipherKeyPair Pair(X25519PrivateKeyParameters key) => new(key.GeneratePublicKey(), key);
    private static AsymmetricCipherKeyPair Pair(X448PrivateKeyParameters key) => new(key.GeneratePublicKey(), key);

    private static KeyMaterial Export(AsymmetricCipherKeyPair pair) => new(
        PemEncoding.WriteString("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetDerEncoded()),
        PemEncoding.WriteString("PRIVATE KEY", PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetDerEncoded()));

    internal static AsymmetricKeyParameter ReadKey(string pem, bool privateKey)
    {
        var fields = PemEncoding.Find(pem);
        string expected = privateKey ? "PRIVATE KEY" : "PUBLIC KEY";
        if (pem[fields.Label] != expected) throw new ArgumentException(L("InvalidKey"));
        byte[] der = Convert.FromBase64String(pem[fields.Base64Data]);
        try { return privateKey ? PrivateKeyFactory.CreateKey(der) : PublicKeyFactory.CreateKey(der); }
        finally { if (privateKey) CryptographicOperations.ZeroMemory(der); }
    }
}
