using System.Text.Json.Nodes;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class EllipticCurveCryptographyTests
{
    public static IEnumerable<object[]> SigningAlgorithms => EllipticCurveCryptography.SigningAlgorithms.Select(a => new object[] { a });
    public static IEnumerable<object[]> EncryptionAlgorithms => EllipticCurveCryptography.EncryptionAlgorithms.Select(a => new object[] { a });

    [Theory]
    [MemberData(nameof(SigningAlgorithms))]
    public void SignaturesVerifyAndDetectModifiedMessagesAndWrongKeys(string algorithm)
    {
        var key = KeyGenerator.Generate(algorithm);
        var wrongKey = KeyGenerator.Generate(algorithm);
        string signature = EllipticCurveCryptography.Sign(algorithm, key.PrivateKey, "你好 🔑");
        Assert.True(EllipticCurveCryptography.Verify(algorithm, key.PublicKey, "你好 🔑", signature));
        Assert.False(EllipticCurveCryptography.Verify(algorithm, key.PublicKey, "modified", signature));
        Assert.False(EllipticCurveCryptography.Verify(algorithm, wrongKey.PublicKey, "你好 🔑", signature));
    }

    [Theory]
    [MemberData(nameof(EncryptionAlgorithms))]
    public void EncryptionRoundTripsAndRejectsWrongKeysAndTampering(string algorithm)
    {
        string keyAlgorithm = algorithm.StartsWith("SM2-", StringComparison.Ordinal) ? "SM2" : algorithm;
        var keys = KeyGenerator.Generate(keyAlgorithm);
        string encrypted = EllipticCurveCryptography.Encrypt(algorithm, keys.PublicKey, "你好 🔑" + new string('a', 2000));
        Assert.Equal("你好 🔑" + new string('a', 2000), EllipticCurveCryptography.Decrypt(algorithm, keys.PrivateKey, encrypted));
        Assert.NotEqual(encrypted, EllipticCurveCryptography.Encrypt(algorithm, keys.PublicKey, "你好 🔑" + new string('a', 2000)));
        var wrongKey = KeyGenerator.Generate(keyAlgorithm);
        Assert.ThrowsAny<Exception>(() => EllipticCurveCryptography.Decrypt(algorithm, wrongKey.PrivateKey, encrypted));
        if (algorithm.StartsWith("SM2-", StringComparison.Ordinal))
        {
            var bytes = Convert.FromBase64String(encrypted);
            bytes[^1] ^= 1;
            Assert.ThrowsAny<Exception>(() => EllipticCurveCryptography.Decrypt(algorithm, keys.PrivateKey, Convert.ToBase64String(bytes)));
        }
        else
        {
            foreach (string field in new[] { "ciphertext", "tag", "nonce", "salt", "ephemeralPublicKey" })
            {
                var json = JsonNode.Parse(encrypted)!;
                byte[] bytes = Convert.FromBase64String(json[field]!.GetValue<string>());
                bytes[^1] ^= 1;
                json[field] = Convert.ToBase64String(bytes);
                Assert.ThrowsAny<Exception>(() => EllipticCurveCryptography.Decrypt(algorithm, keys.PrivateKey, json.ToJsonString()));
            }
            var version = JsonNode.Parse(encrypted)!;
            version["version"] = 2;
            Assert.Throws<ArgumentException>(() => EllipticCurveCryptography.Decrypt(algorithm, keys.PrivateKey, version.ToJsonString()));
        }
    }

    [Fact]
    public void Sm2UserIdIsPartOfTheSignature()
    {
        var key = KeyGenerator.Generate("SM2");
        var signature = EllipticCurveCryptography.Sign("SM2", key.PrivateKey, "message", "alice");
        Assert.True(EllipticCurveCryptography.Verify("SM2", key.PublicKey, "message", signature, "alice"));
        Assert.False(EllipticCurveCryptography.Verify("SM2", key.PublicKey, "message", signature, "bob"));
    }

    [Fact]
    public void RejectsMismatchedCurve()
    {
        var key = KeyGenerator.Generate("ECDSA-P256");
        Assert.Throws<ArgumentException>(() => EllipticCurveCryptography.Sign("ECDSA-P384", key.PrivateKey, "message"));
        Assert.Throws<ArgumentException>(() => EllipticCurveCryptography.Encrypt("SM2-C1C3C2", key.PublicKey, "message"));
    }

    [Fact]
    public void Ed25519MatchesRfc8032EmptyMessageVector()
    {
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var privateKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(seed, 0);
        var der = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetDerEncoded();
        var pem = System.Security.Cryptography.PemEncoding.WriteString("PRIVATE KEY", der);
        var signature = EllipticCurveCryptography.Sign("Ed25519", pem, "");
        Assert.Equal("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", Convert.ToHexString(Convert.FromBase64String(signature)).ToLowerInvariant());
    }
}
