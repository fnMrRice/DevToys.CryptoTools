using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace DevToys.CryptoTools.Tests;

public class KeyOutputFormatterTests
{
    [Theory]
    [InlineData("RSA-2048")]
    [InlineData("ECDSA-P256")]
    [InlineData("ECDSA-P384")]
    [InlineData("ECDSA-P521")]
    [InlineData("ECDSA-secp256k1")]
    [InlineData("ECDSA-brainpoolP256r1")]
    [InlineData("ECDH-brainpoolP512r1")]
    [InlineData("SM2")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    [InlineData("X25519")]
    [InlineData("X448")]
    public void PemAndDerFormatsPreserveCanonicalKeyContainers(string algorithm)
    {
        KeyMaterial keys = KeyGenerator.Generate(algorithm);
        byte[] privateDer = ReadDer(keys.PrivateKey);
        byte[] publicDer = ReadDer(keys.PublicKey);
        try
        {
            Assert.Equal(keys.PrivateKey, KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.Pem));
            Assert.Equal(keys.PrivateKey, KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.Pkcs8Pem));
            Assert.Equal(keys.PublicKey, KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.Pem));
            Assert.Equal(Encoding.UTF8.GetBytes(keys.PrivateKey), KeyOutputFormatter.ExportPrivate(keys.PrivateKey, KeyOutputFormat.Pkcs8Pem));
            Assert.Equal(Encoding.UTF8.GetBytes(keys.PublicKey), KeyOutputFormatter.ExportPublic(keys.PublicKey, KeyOutputFormat.Pem));
            Assert.Equal(Convert.ToHexString(privateDer), KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.DerHex));
            Assert.Equal(Convert.ToBase64String(privateDer), KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.DerBase64));
            Assert.Equal(Convert.ToHexString(publicDer), KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.DerHex));
            Assert.Equal(Convert.ToBase64String(publicDer), KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.DerBase64));
            foreach (KeyOutputFormat format in new[] { KeyOutputFormat.DerHex, KeyOutputFormat.DerBase64 })
            {
                byte[] exportedPrivate = KeyOutputFormatter.ExportPrivate(keys.PrivateKey, format);
                try { Assert.Equal(privateDer, exportedPrivate); }
                finally { CryptographicOperations.ZeroMemory(exportedPrivate); }
                Assert.Equal(publicDer, KeyOutputFormatter.ExportPublic(keys.PublicKey, format));
            }
        }
        finally { CryptographicOperations.ZeroMemory(privateDer); }
    }

    [Fact]
    public void RsaTraditionalFormatsPreserveBothKeysAndRemainInteroperable()
    {
        KeyMaterial keys = KeyGenerator.Generate("RSA-2048");
        Assert.True(KeyOutputFormatter.CanUseTraditionalPrivatePem(keys.PrivateKey));
        Assert.True(KeyOutputFormatter.CanUseTraditionalPublicPem(keys.PublicKey));
        string privatePem = KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.TraditionalPem);
        string publicPem = KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.TraditionalPem);
        Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", privatePem);
        Assert.StartsWith("-----BEGIN RSA PUBLIC KEY-----", publicPem);

        using var privateRsa = RSA.Create();
        privateRsa.ImportFromPem(privatePem);
        using var publicRsa = RSA.Create();
        publicRsa.ImportFromPem(publicPem);
        Assert.Equal(keys.PrivateKey, privateRsa.ExportPkcs8PrivateKeyPem());
        Assert.Equal(keys.PublicKey, publicRsa.ExportSubjectPublicKeyInfoPem());
        Assert.Equal(Encoding.UTF8.GetBytes(privatePem), KeyOutputFormatter.ExportPrivate(keys.PrivateKey, KeyOutputFormat.TraditionalPem));
        Assert.Equal(Encoding.UTF8.GetBytes(publicPem), KeyOutputFormatter.ExportPublic(keys.PublicKey, KeyOutputFormat.TraditionalPem));
        byte[] signature = privateRsa.SignData("same key after changing formats"u8, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(publicRsa.VerifyData("same key after changing formats"u8, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Theory]
    [InlineData("ECDSA-P256")]
    [InlineData("ECDSA-P384")]
    [InlineData("ECDSA-P521")]
    [InlineData("ECDSA-secp256k1")]
    [InlineData("ECDH-brainpoolP512r1")]
    [InlineData("SM2")]
    public void EcTraditionalPrivatePemPreservesScalarCurveAndPublicPoint(string algorithm)
    {
        KeyMaterial keys = KeyGenerator.Generate(algorithm);
        Assert.True(KeyOutputFormatter.CanUseTraditionalPrivatePem(keys.PrivateKey));
        Assert.False(KeyOutputFormatter.CanUseTraditionalPublicPem(keys.PublicKey));
        string pem = KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.TraditionalPem);
        Assert.StartsWith("-----BEGIN EC PRIVATE KEY-----", pem);

        using var reader = new StringReader(pem);
        object parsed = new PemReader(reader).ReadObject();
        var pair = Assert.IsType<AsymmetricCipherKeyPair>(parsed);
        var privateKey = Assert.IsType<ECPrivateKeyParameters>(pair.Private);
        var publicKey = Assert.IsType<ECPublicKeyParameters>(pair.Public);
        var originalPrivate = Assert.IsType<ECPrivateKeyParameters>(KeyGenerator.ReadKey(keys.PrivateKey, true));
        var originalPublic = Assert.IsType<ECPublicKeyParameters>(KeyGenerator.ReadKey(keys.PublicKey, false));
        Assert.Equal(originalPrivate.D, privateKey.D);
        Assert.Equal(originalPrivate.Parameters.N, privateKey.Parameters.N);
        Assert.Equal(originalPrivate.Parameters.G, privateKey.Parameters.G);
        Assert.Equal(originalPublic.Q, publicKey.Q);

        byte[] originalDer = ReadDer(keys.PrivateKey);
        byte[] traditionalDer = ReadDer(pem);
        try
        {
            var original = ECPrivateKeyStructure.GetInstance(PrivateKeyInfo.GetInstance(originalDer).ParsePrivateKey());
            var traditional = ECPrivateKeyStructure.GetInstance(traditionalDer);
            Assert.Equal(original.PrivateKey.GetOctets(), traditional.PrivateKey.GetOctets());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalDer);
            CryptographicOperations.ZeroMemory(traditionalDer);
        }
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.TraditionalPem));
    }

    [Fact]
    public void EcTraditionalPemRetainsLeadingZeroScalarBytesAndImportsIntoDotNet()
    {
        byte[] scalar = new byte[32];
        scalar[^1] = 1;
        byte[] generator = SecNamedCurves.GetByName("secp256r1").G.GetEncoded(false);
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = scalar,
            Q = new ECPoint { X = generator[1..33], Y = generator[33..65] }
        };
        using var original = ECDsa.Create(parameters);
        string canonical = original.ExportPkcs8PrivateKeyPem();
        string traditional = KeyOutputFormatter.FormatPrivate(canonical, KeyOutputFormat.TraditionalPem);
        byte[] der = ReadDer(traditional);
        try
        {
            var sec1 = ECPrivateKeyStructure.GetInstance(der);
            Assert.Equal(scalar, sec1.PrivateKey.GetOctets());
            using var imported = ECDsa.Create();
            imported.ImportFromPem(traditional);
            Assert.Equal(original.ExportSubjectPublicKeyInfoPem(), imported.ExportSubjectPublicKeyInfoPem());
            Assert.Equal(scalar, imported.ExportParameters(true).D);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
            CryptographicOperations.ZeroMemory(der);
        }
    }

    [Theory]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    [InlineData("X25519")]
    [InlineData("X448")]
    public void ModernCurveKeysNeverOfferAnUnsupportedTraditionalContainer(string algorithm)
    {
        KeyMaterial keys = KeyGenerator.Generate(algorithm);
        Assert.False(KeyOutputFormatter.CanUseTraditionalPrivatePem(keys.PrivateKey));
        Assert.False(KeyOutputFormatter.CanUseTraditionalPublicPem(keys.PublicKey));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.TraditionalPem));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPrivate(keys.PrivateKey, KeyOutputFormat.TraditionalPem));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.TraditionalPem));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPublic(keys.PublicKey, KeyOutputFormat.TraditionalPem));
    }

    [Fact]
    public void EncryptedPkcs8IsNeverDecryptedOrReencryptedWhileChangingOutputFormat()
    {
        using var original = RSA.Create(2048);
        const string password = "format password🔐";
        string canonical = original.ExportEncryptedPkcs8PrivateKeyPem(password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));
        byte[] expectedDer = ReadDer(canonical);
        try
        {
            Assert.False(KeyOutputFormatter.CanUseTraditionalPrivatePem(canonical));
            foreach (KeyOutputFormat format in new[] { KeyOutputFormat.Pem, KeyOutputFormat.Pkcs8Pem })
            {
                Assert.Equal(canonical, KeyOutputFormatter.FormatPrivate(canonical, format));
                byte[] exported = KeyOutputFormatter.ExportPrivate(canonical, format);
                try { Assert.Equal(Encoding.UTF8.GetBytes(canonical), exported); }
                finally { CryptographicOperations.ZeroMemory(exported); }
            }
            foreach (KeyOutputFormat format in new[] { KeyOutputFormat.DerHex, KeyOutputFormat.DerBase64 })
            {
                byte[] exported = KeyOutputFormatter.ExportPrivate(canonical, format);
                try
                {
                    Assert.Equal(expectedDer, exported);
                    using var imported = RSA.Create();
                    imported.ImportEncryptedPkcs8PrivateKey(password, exported, out int bytesRead);
                    Assert.Equal(exported.Length, bytesRead);
                    Assert.Equal(original.ExportSubjectPublicKeyInfoPem(), imported.ExportSubjectPublicKeyInfoPem());
                }
                finally { CryptographicOperations.ZeroMemory(exported); }
            }
            Assert.Equal(Convert.ToHexString(expectedDer), KeyOutputFormatter.FormatPrivate(canonical, KeyOutputFormat.DerHex));
            Assert.Equal(Convert.ToBase64String(expectedDer), KeyOutputFormatter.FormatPrivate(canonical, KeyOutputFormat.DerBase64));
            Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPrivate(canonical, KeyOutputFormat.TraditionalPem));
            Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPrivate(canonical, KeyOutputFormat.TraditionalPem));
        }
        finally { CryptographicOperations.ZeroMemory(expectedDer); }
    }

    [Fact]
    public void RepeatedFormatChangesRetainTheSameKeyAndReturnIndependentExportBuffers()
    {
        KeyMaterial keys = KeyGenerator.Generate("ECDSA-P256");
        byte[] expected = ReadDer(keys.PrivateKey);
        byte[] first = KeyOutputFormatter.ExportPrivate(keys.PrivateKey, KeyOutputFormat.DerHex);
        byte[] second = KeyOutputFormatter.ExportPrivate(keys.PrivateKey, KeyOutputFormat.DerBase64);
        try
        {
            Assert.NotSame(first, second);
            first[0] ^= 0xFF;
            Assert.Equal(expected, second);
            foreach (KeyOutputFormat format in new[] { KeyOutputFormat.TraditionalPem, KeyOutputFormat.DerHex, KeyOutputFormat.Pkcs8Pem, KeyOutputFormat.DerBase64 })
            {
                string formatted = KeyOutputFormatter.FormatPrivate(keys.PrivateKey, format);
                if (format == KeyOutputFormat.TraditionalPem)
                {
                    using var imported = ECDsa.Create();
                    imported.ImportFromPem(formatted);
                    Assert.Equal(keys.PublicKey, imported.ExportSubjectPublicKeyInfoPem());
                }
            }
            Assert.Equal(keys.PrivateKey, KeyOutputFormatter.FormatPrivate(keys.PrivateKey, KeyOutputFormat.Pkcs8Pem));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid PEM")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----")]
    [InlineData("-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----")]
    public void InvalidCanonicalKeysAreRejectedWithoutOfferingTraditionalFormats(string? pem)
    {
        Assert.False(KeyOutputFormatter.CanUseTraditionalPrivatePem(pem!));
        Assert.False(KeyOutputFormatter.CanUseTraditionalPublicPem(pem!));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPrivate(pem!, KeyOutputFormat.Pkcs8Pem));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPublic(pem!, KeyOutputFormat.Pem));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPrivate(pem!, KeyOutputFormat.DerHex));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPublic(pem!, KeyOutputFormat.DerBase64));
    }

    [Fact]
    public void UnsupportedFormatValuesAndPublicPkcs8AreRejected()
    {
        KeyMaterial keys = KeyGenerator.Generate("Ed25519");
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPrivate(keys.PrivateKey, (KeyOutputFormat)999));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPublic(keys.PublicKey, (KeyOutputFormat)999));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPrivate(keys.PrivateKey, (KeyOutputFormat)999));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.ExportPublic(keys.PublicKey, (KeyOutputFormat)999));
        Assert.Throws<ArgumentException>(() => KeyOutputFormatter.FormatPublic(keys.PublicKey, KeyOutputFormat.Pkcs8Pem));
    }

    private static byte[] ReadDer(string pem)
    {
        PemFields fields = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }
}
