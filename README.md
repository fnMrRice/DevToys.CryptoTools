# DevToys.CryptoTools

Cryptography extension for DevToys 2.0, targeting .NET 8 and `DevToys.Api 2.0.10-preview`.
English is the default language; Simplified Chinese follows the DevToys UI culture. Other languages fall back to English.

## Tools

| Group | Tool | Algorithms |
| --- | --- | --- |
| Generators | Key generator | Asymmetric pairs only: RSA 2048/3072/4096; ECDSA/ECDH NIST P-256/P-384/P-521, secp256k1, Brainpool P256r1/P384r1/P512r1; Ed25519/Ed448; X25519/X448; SM2 |
| Generators | Certificate request generator | PKCS#10 CSR from generated or imported key pairs; subject, SAN and requested extensions |
| Generators | Certificate generator | Self-signed or CA-issued X.509, including issuance from a verified CSR; RSA/RSA-PSS, ECDSA, Ed25519/Ed448 and SM2/SM3 |
| Generators | Cyclic redundancy check (CRC) / 循环冗余校验 | Standard presets and custom polynomials, widths 1–64 bits, Init/RefIn/RefOut/XorOut |
| Cryptography / 加解密 | RSA algorithms / RSA 算法 | OAEP SHA-256/384/512, PKCS#1 v1.5 encryption; PSS and PKCS#1 v1.5 signatures with SHA-256/384/512; PEM/Base64/Hex public keys, certificates or modulus/exponent |
| Cryptography / 加解密 | Elliptic curve algorithms / 椭圆曲线算法 | Encrypt/decrypt with ECDH, X25519/X448 and SM2; sign/verify with ECDSA, Ed25519/Ed448 and SM2; public keys from PEM/Base64/Hex, certificates or X/Y coordinates |
| Cryptography / 加解密 | Symmetric key algorithms / 对称密钥算法 | AES, SM4, Camellia, ARIA, Twofish, Serpent, Blowfish, CAST5, DES, TripleDES, RC2, ChaCha20, XChaCha20, Salsa20 and XSalsa20; compatible block/stream/AEAD modes |

## Install and try

1. Open **Manage extensions** in DevToys and install `DevToys.CryptoTools.0.3.12.nupkg` from `artifacts/`.
2. Restart DevToys. Key, certificate request, certificate and CRC tools appear under **Generators**; RSA, symmetric key algorithms and elliptic curve algorithms appear under **Cryptography** (加解密 in Chinese).
3. Generate an asymmetric pair using the algorithm needed by your operation. Choose RSA, ECDSA, ECDH, Ed25519, Ed448, X25519, X448 or SM2 on the algorithm card; expand it to select the RSA key size, EC curve and optional private key password. Actions are above the editors, with the private key on the left and public key on the right. Copy the public PEM key to encrypt/verify, or the private PEM key to decrypt/sign. The symmetric page defaults to **Hex** for both key and IV. Text keys and IVs use their UTF-8 bytes directly, without password derivation.
4. Encryption and signing accept UTF-8 text by default. On the symmetric page, input and output are side by side and each has a **Base64 / Hex / Text (UTF-8)** selector. **Use output as input** transfers the result and switches the encodings for decryption. To verify signatures, enter the original text in **Input** and the Base64 signature in **Signature**.
5. Certificates and CSRs are PEM text. Save the certificate/request and its matching PKCS#8 private key separately. A new key is created only when no subject private key is imported. The **Create certificate request** button on the key generator opens the CSR form with the existing pair; **Use CSR to issue certificate** opens certificate issuance with that request. These are the actual destination forms embedded in the current tool with a **Back** button; no clipboard or sidebar navigation is needed. Each form is also available separately in Generators.

The key generator accepts an optional password. When generating, leaving it empty produces an unencrypted PKCS#8 private key; entering a password produces an encrypted PKCS#8 PEM (`ENCRYPTED PRIVATE KEY`) using PBES2, AES-256-CBC and PBKDF2-HMAC-SHA256 with a fresh salt and IV. The password is applied at generation time. Changing it afterwards affects the next generated pair; exporting always preserves the already generated private key and its original password protection. The public key is unchanged. The direct CSR action uses the generated pair in memory, including when the exported private key is password protected.

Each key editor has its own output format selector. Switching formats converts the existing key without generating a new pair or changing its password. Private keys support PKCS#8 PEM and DER shown as Hex or Base64; unencrypted RSA and EC keys also support traditional PKCS#1 / SEC1 PEM. Public keys support SubjectPublicKeyInfo PEM and DER shown as Hex or Base64; RSA public keys can also use PKCS#1 PEM. Password-protected private keys retain their encrypted PKCS#8 structure in both PEM and DER.

Click **Export key pair** to open the export dialog. Enter the base file name and choose an output directory there, then confirm **Export**. Files are saved as `<name>.key` (private) and `<name>.pub` (public), using each editor's selected format. PEM exports are text; DER exports contain the binary DER bytes, regardless of whether the editor displays them as Hex or Base64. Existing files are not overwritten; a conflict keeps the dialog open so the name can be corrected. Cancelling the dialog writes no files.

## Elliptic curve algorithms

The page uses native setting cards and side-by-side input/output. Select **Encrypt / Decrypt / Sign / Verify** on the visible Mode card; choose the algorithm in the **Parameters** card header and expand it for the public-key source, encodings and SM2 user ID. Options appear only for the modes and algorithms that use them. Switching between ECDH and ECDSA preserves the selected curve. Key material and file import remain below the settings, with a separate private-key input for decryption and signing. Drop unencrypted PEM/DER keys or PEM/DER X.509 `.cer` / `.crt` certificates into the file import area; certificates are converted to SPKI public keys. PKCS#8 and SEC1 EC private keys are normalized automatically. PFX/PKCS#12 and password-encrypted key files are not supported by this importer.

Public key data accepts **PEM / Base64 / Hex**. Base64 and Hex can encode SPKI DER, certificate DER or a raw public key: prime-curve SEC1 compressed/uncompressed points or X||Y, Ed25519/Ed448 raw public keys, and X25519/X448 raw public keys. Private material is rejected in public-key mode. Dropping a file resets its encoding to PEM.

**X/Y coordinates** are also available for encryption or verification on the listed prime curves. Choose Hex or Base64 for unsigned big-endian coordinates; Hex accepts optional whitespace and `0x`. Coordinates are checked against the selected curve and subgroup. EdDSA/XDH use their standard encoded public keys instead of Cartesian input. The SM2 user ID appears only for SM2 signing/verification. **Use output as input** switches encryption to decryption; after signing, it switches to verification and transfers the signature while preserving the original message.

## RSA algorithms

The RSA page matches the elliptic curve layout: the Mode card selects **Encrypt / Decrypt / Sign / Verify**, and the expandable **Parameters** card contains padding, hash, public-key source and encoding settings. Key material stays below the settings, followed by side-by-side input/output. Encryption/decryption show encryption padding; signing/verification show signature padding and hash. Only verification displays the signature input. **Use output as input** switches encryption to decryption, or transfers a generated signature into verification while preserving the message.

For encryption and verification, choose **Key / certificate** or **Modulus / exponent (n/e)**. Public data accepts PEM, Base64 or Hex SPKI/PKCS#1 public keys or certificate DER. Modulus/exponent are unsigned big-endian integers in Hex or Base64; Hex permits optional whitespace and `0x`. Decryption/signing use a separate private key field supporting unencrypted PKCS#8 and PKCS#1 PEM/DER. File import uses the native drag/drop area and resets public data encoding to PEM. Certificates provide public keys only; private material and other key types are rejected as RSA public inputs.

## Certificate and CSR options

The two-column builders expose subject CN/O/OU/C/ST/L plus full DN override; automatic or SHA-256/384/512 signature hashes, RSA-PSS, SAN DNS/IP/email/URI, all nine KU flags, common EKU switches (including document signing), custom EKU OIDs, CA/path length, extension critical flags and a custom OID/Base64-DER extension. Certificate issuance additionally exposes UTC validity dates, random or custom Hex serial numbers and issuer DN. Presets cover TLS server/client, code/document signing, email, timestamping and CA usage; fields remain editable.

Import a private key on the CSR form to sign with an existing pair. Dropping a CSR on the certificate form verifies its signature and loads its editable request fields. An external CSR does not contain a private key: import the matching subject private key to self-sign, or supply an issuer CA certificate and its matching private key to issue it. Issuer key correspondence, CA constraints and validity bounds are checked. Requested extensions are shown as editable options and the certificate is generated only when **Generate certificate** is clicked.

All operations run locally. Inputs, private keys and plaintext are not logged or saved in settings. **Clear** removes the current tool's text; copied clipboard contents remain under your control.

Tool pages use natural-height, top-aligned sections and scroll when the content exceeds the window. Editor regions have bounded heights, while key import, certificate options and expanded parameters grow with their content. CSR handoffs add a navigation row only while a destination form is open.

## Formats and interoperability

- Public keys: SPKI `PUBLIC KEY` PEM. Private keys: unencrypted PKCS#8 `PRIVATE KEY` PEM. RSA additionally accepts the PEM forms supported by .NET `ImportFromPem`.
- RSA ciphertext and signatures: Base64. RSA is limited to short messages; the tool checks the selected padding's byte limit before encrypting.
- ECDSA and SM2 signatures: ASN.1 DER `(r, s)`, Base64 encoded. Ed25519 and Ed448: pure EdDSA, raw signature bytes in Base64, empty Ed448 context. ECDSA hash is SHA-256/384/512 for P-256/384/521 respectively.
- SM2: sm2p256v1 curve, SM3, UTF-8 user ID (default `1234567812345678`). Signing and verification require the same ID. Encryption uses Base64 raw C1C3C2 or C1C2C3 with an uncompressed C1 point including the `04` prefix; it does not use the hybrid JSON format.
- ECDH/XDH hybrid ciphertext: CryptoTools JSON envelope, version 1. It includes `algorithm`, `ephemeralPublicKey` (Base64 SPKI DER), `salt`, `nonce`, `tag`, and `ciphertext` (all Base64). A fresh ephemeral key, 32-byte salt and 12-byte nonce are generated per message. The raw shared secret feeds HKDF-SHA256 to derive a 32-byte AES-GCM key. Both HKDF info and GCM additional authenticated data are UTF-8 `DevToys.CryptoTools.EC.v1|` followed by the exact algorithm name. ECDH secrets are fixed-width, unsigned big-endian; XDH secrets follow RFC 7748. Tags are 16 bytes. This is a plugin-specific format, not a generic ECIES standard. It does not authenticate the sender.
- Symmetric page: select the algorithm in the native setting card header and expand the card for mode, padding and key length. Key and IV inputs stay below the card and outside its collapsible settings, followed by side-by-side input/output. The empty IV field shows an in-field ghost hint. Output is raw ciphertext in the selected encoding; binary ciphertext should use Base64 or Hex, while Text output requires valid UTF-8 bytes. Authenticated modes append their tag to the ciphertext, with empty additional authenticated data. See the supported mode and key-size tables below.
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

Only compatible choices are offered. Algorithm, key length, mode and padding use labels above their full-width selectors. Key length is explicitly configured in bits and offers only sizes supported by the selected algorithm; fixed-size algorithms show a single disabled choice. After decoding Hex/Base64/UTF-8 key input, short keys are right-padded with zero bytes and overlong keys have their tail truncated to the selected size. The original input remains unchanged. This key normalization is separate from message padding; select the original key size when decrypting existing ciphertext.

**Random key** generates exactly the configured number of random bytes. If Text encoding was selected, generation switches the field to Hex so arbitrary random bytes remain reversible. Symmetric random keys are generated here; the Generators key page only produces asymmetric public/private pairs.

ECB/CBC support PKCS7, None, Zeros, ANSIX923 and ISO10126 message padding. Other modes use no padding. Without padding, ECB/CBC input must align to the cipher's block size; zero padding removes all trailing zero bytes on decryption and cannot preserve them unambiguously. DES, TripleDES and RC2 are included for legacy interoperability.

| Algorithm | Configurable normalized key sizes (bytes; UI displays bits) |
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

## Cyclic redundancy check (CRC)

The Generators CRC page uses the same setting-card layout as the official hash generator: select the algorithm on the configuration card, and expand it to edit the width, polynomial, initial value, input/output reflection and final XOR. Changing a parameter switches the selector to **Custom** and clears the published preset check value.

Enter UTF-8 text, Hex bytes or Base64 bytes on the left, or drop a file on the right. Files are read as raw bytes in 64 KiB chunks without loading the entire file into memory; the text encoding selector does not affect file bytes. Selecting a file clears the manual input. Typing in the text box clears the selected file. Results update automatically when the input, file, algorithm or parameters change; a superseded file calculation is cancelled.

Polynomials, initial values and final XOR are unsigned Hex values, optionally prefixed with `0x`. The polynomial uses its normal representation without the implicit highest `x^width` term; for example, CRC-16/MODBUS uses `8005`, with reflection controlled by the switches. The width may be 1–64 bits, including sub-byte widths. Values outside the width and a zero polynomial are rejected.

Output is fixed-width uppercase Hex. The optional **Checksum to verify (Hex)** field automatically compares an expected checksum with the current result whenever either value changes, and accepts an optional `0x` prefix. The displayed preset check is the standard result for ASCII `123456789`, not the result of the current input. Preset parameters and check values are based on the [CRC RevEng catalogue](https://reveng.sourceforge.io/crc-catalogue/all.htm), and every included preset is tested against its published check value.

## Build and test

Use a .NET SDK capable of targeting .NET 8. No native dependencies are required beyond the runtime's cryptography providers.

```powershell
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
dotnet pack src/DevToys.CryptoTools -c Release --no-build -o artifacts
pwsh -File scripts/Verify-Package.ps1 -PackagePath artifacts/DevToys.CryptoTools.0.3.12.nupkg
```

Tests cover key import, certificate/CSR signatures, algorithm round trips, invalid key types, message limits, tampering, SM2 IDs, RFC 8032 and NIST vectors, MEF discovery, language fallback, symmetric page encodings, IV generation, CRC preset checks, streamed file input, checksum comparison and button workflows. GitHub Actions runs the suite on Windows, Linux and macOS.

The package bundles Bouncy Castle and its license plus the Chinese satellite assembly. DevToys supplies its API and framework dependencies; the package does not require a NuGet dependency restore when installed.

## Project structure

- `src/DevToys.CryptoTools/Cryptography`: cryptographic services.
- `src/DevToys.CryptoTools/Tools`: seven MEF-exported GUI tools.
- `src/DevToys.CryptoTools/Localization`: English resources and `Strings.zh-Hans.resx`.
- `tests/DevToys.CryptoTools.Tests`: algorithm and plugin integration tests.

New languages can be added as `Strings.<culture>.resx`, using the English resource keys. Host language changes take effect after recreating the tools/restarting DevToys.

Built using the [DevToys extension API](https://devtoys.app/doc/articles/extension-development/getting-started/create-an-extension.html) and [Bouncy Castle for C#](https://www.bouncycastle.org/download/bouncy-castle-c/).
