using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record EcEnvelope(int Version, string Algorithm, string EphemeralPublicKey, string Salt, string Nonce, string Tag, string Ciphertext);

internal static class EllipticCurveCryptography
{
    internal static readonly string[] SigningAlgorithms = [.. EcDomains.Curves.Select(curve => "ECDSA-" + curve), "Ed25519", "Ed448", "SM2"];
    internal static readonly string[] EncryptionAlgorithms = [.. EcDomains.Curves.Select(curve => "ECDH-" + curve), "X25519", "X448", "SM2-C1C3C2", "SM2-C1C2C3"];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static string Sign(string algorithm, string pem, string text, string sm2Id = "1234567812345678")
    {
        var key = KeyGenerator.ReadKey(pem, true);
        ValidateKey(algorithm, key, true);
        ISigner signer = Signer(algorithm);
        ICipherParameters parameters = algorithm is "Ed25519" or "Ed448" ? key : new ParametersWithRandom(key, new SecureRandom());
        if (algorithm == "SM2") parameters = new ParametersWithID(parameters, Encoding.UTF8.GetBytes(sm2Id));
        signer.Init(true, parameters);
        byte[] data = Encoding.UTF8.GetBytes(text);
        signer.BlockUpdate(data, 0, data.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    internal static bool Verify(string algorithm, string pem, string text, string signature, string sm2Id = "1234567812345678")
    {
        var key = KeyGenerator.ReadKey(pem, false);
        ValidateKey(algorithm, key, false);
        ISigner signer = Signer(algorithm);
        ICipherParameters parameters = key;
        if (algorithm == "SM2") parameters = new ParametersWithID(key, Encoding.UTF8.GetBytes(sm2Id));
        signer.Init(false, parameters);
        byte[] data = Encoding.UTF8.GetBytes(text);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(Convert.FromBase64String(signature));
    }

    internal static string Encrypt(string algorithm, string pem, string text)
    {
        if (!EncryptionAlgorithms.Contains(algorithm)) throw new ArgumentException(L("InvalidAlgorithm"));
        var recipient = KeyGenerator.ReadKey(pem, false);
        ValidateKey(algorithm, recipient, false);
        if (algorithm.StartsWith("SM2-", StringComparison.Ordinal))
        {
            var engine = Sm2Engine(algorithm);
            engine.Init(true, new ParametersWithRandom(recipient, new SecureRandom()));
            var input = Encoding.UTF8.GetBytes(text);
            return Convert.ToBase64String(engine.ProcessBlock(input, 0, input.Length));
        }
        var ephemeral = GenerateAgreementKey(algorithm);
        byte[] secret = SharedSecret(algorithm, ephemeral.Private, recipient);
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, salt, Context(algorithm));
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] plaintext = Encoding.UTF8.GetBytes(text);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Context(algorithm));
            return JsonSerializer.Serialize(new EcEnvelope(1, algorithm,
                Convert.ToBase64String(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ephemeral.Public).GetDerEncoded()),
                Convert.ToBase64String(salt), Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(ciphertext)), JsonOptions);
        }
        finally { CryptographicOperations.ZeroMemory(secret); CryptographicOperations.ZeroMemory(key); }
    }

    internal static string Decrypt(string algorithm, string pem, string text)
    {
        if (!EncryptionAlgorithms.Contains(algorithm)) throw new ArgumentException(L("InvalidAlgorithm"));
        var recipient = KeyGenerator.ReadKey(pem, true);
        ValidateKey(algorithm, recipient, true);
        if (algorithm.StartsWith("SM2-", StringComparison.Ordinal))
        {
            var engine = Sm2Engine(algorithm);
            engine.Init(false, recipient);
            byte[] input = Convert.FromBase64String(text);
            return new UTF8Encoding(false, true).GetString(engine.ProcessBlock(input, 0, input.Length));
        }
        var envelope = JsonSerializer.Deserialize<EcEnvelope>(text, JsonOptions);
        if (envelope is null || envelope.Version != 1 || envelope.Algorithm != algorithm
            || envelope.EphemeralPublicKey is null || envelope.Salt is null || envelope.Nonce is null || envelope.Tag is null || envelope.Ciphertext is null)
            throw new ArgumentException(L("InvalidEnvelope"));
        var ephemeral = PublicKeyFactory.CreateKey(Convert.FromBase64String(envelope.EphemeralPublicKey));
        ValidateKey(algorithm, ephemeral, false);
        byte[] salt = Convert.FromBase64String(envelope.Salt);
        byte[] nonce = Convert.FromBase64String(envelope.Nonce);
        byte[] tag = Convert.FromBase64String(envelope.Tag);
        if (salt.Length != 32 || nonce.Length != 12 || tag.Length != 16) throw new ArgumentException(L("InvalidEnvelope"));
        byte[] secret = SharedSecret(algorithm, recipient, ephemeral);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, salt, Context(algorithm));
        try
        {
            byte[] ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            byte[] plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Context(algorithm));
            return new UTF8Encoding(false, true).GetString(plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(secret); CryptographicOperations.ZeroMemory(key); }
    }

    private static byte[] Context(string algorithm) => Encoding.UTF8.GetBytes("DevToys.CryptoTools.EC.v1|" + algorithm);

    private static AsymmetricCipherKeyPair GenerateAgreementKey(string algorithm)
    {
        if (algorithm is "X25519" or "X448") return KeyGenerator.GenerateModernCurve(algorithm);
        var material = KeyGenerator.Generate(algorithm);
        return new(KeyGenerator.ReadKey(material.PublicKey, false), KeyGenerator.ReadKey(material.PrivateKey, true));
    }

    private static byte[] SharedSecret(string algorithm, AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey)
    {
        if (algorithm is "X25519" or "X448")
        {
            IRawAgreement agreement = algorithm == "X25519" ? new X25519Agreement() : new X448Agreement();
            agreement.Init(privateKey);
            var secret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKey, secret, 0);
            return secret;
        }
        var ecdh = new ECDHBasicAgreement();
        ecdh.Init(privateKey);
        return Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(ecdh.GetFieldSize(), ecdh.CalculateAgreement(publicKey));
    }

    private static ISigner Signer(string algorithm)
    {
        if (algorithm.StartsWith("ECDSA-", StringComparison.Ordinal))
        {
            int bits = EcDomains.ForAlgorithm(algorithm).N.BitLength;
            return SignerUtilities.GetSigner((bits <= 256 ? "SHA256" : bits <= 384 ? "SHA384" : "SHA512") + "withECDSA");
        }
        return algorithm switch
        {
            "Ed25519" => new Ed25519Signer(),
            "Ed448" => new Ed448Signer([]),
            "SM2" => new SM2Signer(),
            _ => throw new ArgumentException(L("InvalidAlgorithm"))
        };
    }

    private static SM2Engine Sm2Engine(string algorithm) => new(algorithm == "SM2-C1C3C2" ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);

    private static void ValidateKey(string algorithm, AsymmetricKeyParameter key, bool isPrivate)
    {
        if (key.IsPrivate != isPrivate) throw new ArgumentException(L("InvalidKey"));
        bool valid = algorithm switch
        {
            "Ed25519" => key is Ed25519PrivateKeyParameters or Ed25519PublicKeyParameters,
            "Ed448" => key is Ed448PrivateKeyParameters or Ed448PublicKeyParameters,
            "X25519" => key is X25519PrivateKeyParameters or X25519PublicKeyParameters,
            "X448" => key is X448PrivateKeyParameters or X448PublicKeyParameters,
            _ => ValidateEcDomain(algorithm, key)
        };
        if (!valid) throw new ArgumentException(L("InvalidKey"));
    }

    private static bool ValidateEcDomain(string algorithm, AsymmetricKeyParameter key)
    {
        if (key is not ECKeyParameters ec || !EcDomains.SupportsCoordinates(algorithm)) return false;
        var expected = EcDomains.ForAlgorithm(algorithm);
        return ec.Parameters.Equals(expected);
    }
}
