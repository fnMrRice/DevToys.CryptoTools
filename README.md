# DevToys.CryptoTools

Cryptography extension for DevToys 2.0, targeting .NET 8 and `DevToys.Api 2.0.10-preview`.
English is the default language; Simplified Chinese follows the DevToys UI culture. Other languages fall back to English.

## Tools

| Group | Tool | Algorithms |
| --- | --- | --- |
| Generators | Key generator | RSA 2048/3072/4096; ECDSA/ECDH NIST P-256/P-384/P-521, secp256k1, Brainpool P256r1/P384r1/P512r1; Ed25519/Ed448; X25519/X448; SM2; AES 128/192/256; ChaCha20; SM4 |
| Generators | Certificate request generator | PKCS#10 CSR from generated or imported key pairs; subject, SAN and requested extensions |
| Generators | Certificate generator | Self-signed or CA-issued X.509, including issuance from a verified CSR; RSA/RSA-PSS, ECDSA, Ed25519/Ed448 and SM2/SM3 |
| Cryptography / 加解密 | RSA | OAEP SHA-256/384/512, PKCS#1 v1.5 encryption; PSS and PKCS#1 v1.5 signatures with SHA-256/384/512 |
| Cryptography / 加解密 | Elliptic curve algorithms / 椭圆曲线算法 | Encrypt/decrypt with ECDH, X25519/X448 and SM2; sign/verify with ECDSA, Ed25519/Ed448 and SM2; public keys from PEM/Base64/Hex, certificates or X/Y coordinates |
| Cryptography / 加解密 | Symmetric key algorithms / 对称密钥算法 | AES, SM4, Camellia, ARIA, Twofish, Serpent, Blowfish, CAST5, DES, TripleDES, RC2, ChaCha20, XChaCha20, Salsa20 and XSalsa20; compatible block/stream/AEAD modes |

## Install and try

1. Open **Manage extensions** in DevToys and install `DevToys.CryptoTools.0.3.4.nupkg` from `artifacts/`.
2. Restart DevToys. Key, certificate request and certificate tools appear under **Generators**; RSA, symmetric key algorithms and elliptic curve algorithms appear under **Cryptography** (加解密 in Chinese).
3. Generate a key using the algorithm needed by your operation. Copy the public PEM key to encrypt/verify, or the private PEM key to decrypt/sign. The symmetric page defaults to **Hex** for both key and IV; choose **Base64** when pasting a key from the key generator. Text keys and IVs use their UTF-8 bytes directly, without password derivation.
4. Encryption and signing accept UTF-8 text by default. On the symmetric page, input and output are side by side and each has a **Base64 / Hex / Text (UTF-8)** selector. **Use output as input** transfers the result and switches the encodings for decryption. To verify signatures, enter the original text in **Input** and the Base64 signature in **Signature**.
5. Certificates and CSRs are PEM text. Save the certificate/request and its matching PKCS#8 private key separately. A new key is created only when no subject private key is imported. The **Create certificate request** button on the key generator opens the CSR form with the existing pair; **Use CSR to issue certificate** opens certificate issuance with that request. These are the actual destination forms embedded in the current tool with a **Back** button; no clipboard or sidebar navigation is needed. Each form is also available separately in Generators.

## Elliptic curve algorithms

The merged page uses two configuration columns and resizable side-by-side input/output. Select **Encrypt / Decrypt / Sign / Verify** at the upper left. Algorithms are limited to the operations they support; switching between ECDH and ECDSA preserves the selected curve. Encryption and verification show **Public key source** at the upper right; decryption and signing show a separate private-key input. Drop unencrypted PEM/DER keys or PEM/DER X.509 `.cer` / `.crt` certificates into the file import area; certificates are converted to SPKI public keys. PKCS#8 and SEC1 EC private keys are normalized automatically. PFX/PKCS#12 and password-encrypted key files are not supported by this importer.

Public key data accepts **PEM / Base64 / Hex**. Base64 and Hex can encode SPKI DER, certificate DER or a raw public key: prime-curve SEC1 compressed/uncompressed points or X||Y, Ed25519/Ed448 raw public keys, and X25519/X448 raw public keys. Private material is rejected in public-key mode. Dropping a file resets its encoding to PEM.

**X/Y coordinates** are also available for encryption or verification on the listed prime curves. Choose Hex or Base64 for unsigned big-endian coordinates; Hex accepts optional whitespace and `0x`. Coordinates are checked against the selected curve and subgroup. EdDSA/XDH use their standard encoded public keys instead of Cartesian input. The SM2 user ID appears only for SM2 signing/verification. **Use output as input** switches encryption to decryption; after signing, it switches to verification and transfers the signature while preserving the original message.

## Certificate and CSR options

The two-column builders expose subject CN/O/OU/C/ST/L plus full DN override; automatic or SHA-256/384/512 signature hashes, RSA-PSS, SAN DNS/IP/email/URI, all nine KU flags, common EKU switches (including document signing), custom EKU OIDs, CA/path length, extension critical flags and a custom OID/Base64-DER extension. Certificate issuance additionally exposes UTC validity dates, random or custom Hex serial numbers and issuer DN. Presets cover TLS server/client, code/document signing, email, timestamping and CA usage; fields remain editable.

Import a private key on the CSR form to sign with an existing pair. Dropping a CSR on the certificate form verifies its signature and loads its editable request fields. An external CSR does not contain a private key: import the matching subject private key to self-sign, or supply an issuer CA certificate and its matching private key to issue it. Issuer key correspondence, CA constraints and validity bounds are checked. Requested extensions are shown as editable options and the certificate is generated only when **Generate certificate** is clicked.

All operations run locally. Inputs, private keys and plaintext are not logged or saved in settings. **Clear** removes the current tool's text; copied clipboard contents remain under your control.

## Formats and interoperability

- Public keys: SPKI `PUBLIC KEY` PEM. Private keys: unencrypted PKCS#8 `PRIVATE KEY` PEM. RSA additionally accepts the PEM forms supported by .NET `ImportFromPem`.
- RSA ciphertext and signatures: Base64. RSA is limited to short messages; the tool checks the selected padding's byte limit before encrypting.
- ECDSA and SM2 signatures: ASN.1 DER `(r, s)`, Base64 encoded. Ed25519 and Ed448: pure EdDSA, raw signature bytes in Base64, empty Ed448 context. ECDSA hash is SHA-256/384/512 for P-256/384/521 respectively.
- SM2: sm2p256v1 curve, SM3, UTF-8 user ID (default `1234567812345678`). Signing and verification require the same ID. Encryption uses Base64 raw C1C3C2 or C1C2C3 with an uncompressed C1 point including the `04` prefix; it does not use the hybrid JSON format.
- ECDH/XDH hybrid ciphertext: CryptoTools JSON envelope, version 1. It includes `algorithm`, `ephemeralPublicKey` (Base64 SPKI DER), `salt`, `nonce`, `tag`, and `ciphertext` (all Base64). A fresh ephemeral key, 32-byte salt and 12-byte nonce are generated per message. The raw shared secret feeds HKDF-SHA256 to derive a 32-byte AES-GCM key. Both HKDF info and GCM additional authenticated data are UTF-8 `DevToys.CryptoTools.EC.v1|` followed by the exact algorithm name. ECDH secrets are fixed-width, unsigned big-endian; XDH secrets follow RFC 7748. Tags are 16 bytes. This is a plugin-specific format, not a generic ECIES standard. It does not authenticate the sender.
- Symmetric page: raw ciphertext in the selected output encoding, with a separate IV field. The three settings fill the left column; the empty IV field shows an in-field ghost hint. Binary ciphertext should use Base64 or Hex; Text output requires valid UTF-8 bytes. Authenticated modes append their tag to the ciphertext, with empty additional authenticated data. See the supported mode and key-size tables below.
- Leaving IV empty enables automatic random generation and displays the value used. Automatic IVs refresh on each encryption until you enter a manual value; **Random IV** resumes automatic generation. Decryption uses the displayed IV. Keys and IVs support independent Base64, Hex (including whitespace-separated bytes), and UTF-8 text encodings. AES keys are 16/24/32 bytes, SM4 keys 16 bytes, and ChaCha20 keys 32 bytes.
- Compatibility: the symmetric page can still decrypt v0.1.0 JSON envelopes when the matching algorithm/mode is selected. Those envelopes contain their own IV and tag and use UTF-8 `DevToys.CryptoTools.Symmetric.v1|` plus the algorithm name as additional authenticated data. New encryption produces raw ciphertext.

## Symmetric algorithms and modes

| Algorithm family | Modes |
| --- | --- |
| AES, SM4, Camellia, ARIA, Twofish, Serpent | GCM, CBC, ECB, CFB, CFB8, OFB, CTR, CCM, EAX |
| Blowfish, CAST5, DES, TripleDES, RC2 | CBC, ECB, CFB, CFB8, OFB, CTR, EAX |
| ChaCha20 | Poly1305, IETF (raw stream) |
| XChaCha20 | Poly1305, Raw |
| Salsa20, XSalsa20 | Raw |

Only compatible choices are offered. ECB/CBC support PKCS7, None, Zeros, ANSIX923 and ISO10126 padding. Other modes use no padding. Without padding, ECB/CBC input must align to the cipher's block size; zero padding removes all trailing zero bytes on decryption and cannot preserve them unambiguously. DES, TripleDES and RC2 are included for legacy interoperability.

| Algorithm | Accepted key sizes (bytes) |
| --- | --- |
| AES, Camellia, ARIA, Twofish, Serpent | 16, 24, 32 |
| SM4 | 16 |
| Blowfish | 4–56 |
| CAST5 | 5–16 |
| DES | 8 |
| TripleDES | 16, 24 |
| RC2 | 1–128 |
| ChaCha20, XChaCha20, XSalsa20 | 32 |
| Salsa20 | 16, 32 |

ECB uses no IV. CBC/CFB/OFB/CTR use an IV equal to the block size (8 or 16 bytes). CFB uses full-block feedback (CFB64/CFB128); CFB8 is separate. CTR interprets the full IV as a big-endian initial counter. GCM, CCM and ChaCha20 use 12-byte nonces; XChaCha20/XSalsa20 use 24 bytes, Salsa20 uses 8 bytes. EAX uses a block-sized nonce. GCM/CCM/Poly1305 tags are 16 bytes; EAX tags equal the block size. Raw stream modes start at counter zero. **Only GCM, CCM, EAX and Poly1305 authenticate ciphertext.**

## Build and test

Use a .NET SDK capable of targeting .NET 8. No native dependencies are required beyond the runtime's cryptography providers.

```powershell
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
dotnet pack src/DevToys.CryptoTools -c Release --no-build -o artifacts
pwsh -File scripts/Verify-Package.ps1 -PackagePath artifacts/DevToys.CryptoTools.0.3.4.nupkg
```

Tests cover key import, certificate/CSR signatures, algorithm round trips, invalid key types, message limits, tampering, SM2 IDs, RFC 8032 and NIST vectors, MEF discovery, language fallback, symmetric page encodings, IV generation and button workflows. GitHub Actions runs the suite on Windows, Linux and macOS.

The package bundles Bouncy Castle and its license plus the Chinese satellite assembly. DevToys supplies its API and framework dependencies; the package does not require a NuGet dependency restore when installed.

## Project structure

- `src/DevToys.CryptoTools/Cryptography`: cryptographic services.
- `src/DevToys.CryptoTools/Tools`: six MEF-exported GUI tools.
- `src/DevToys.CryptoTools/Localization`: English resources and `Strings.zh-Hans.resx`.
- `tests/DevToys.CryptoTools.Tests`: algorithm and plugin integration tests.

New languages can be added as `Strings.<culture>.resx`, using the English resource keys. Host language changes take effect after recreating the tools/restarting DevToys.

Built using the [DevToys extension API](https://devtoys.app/doc/articles/extension-development/getting-started/create-an-extension.html) and [Bouncy Castle for C#](https://www.bouncycastle.org/download/bouncy-castle-c/).
