using System.Globalization;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record CrcParameters(
    int Width,
    ulong Polynomial,
    ulong Initial,
    bool ReflectInput,
    bool ReflectOutput,
    ulong XorOut);

internal sealed record CrcPreset(string Name, CrcParameters Parameters, ulong Check);

internal static class CrcCalculator
{
    // Parameters and the CRC of ASCII "123456789" come from the CRC RevEng catalogue:
    // https://reveng.sourceforge.io/crc-catalogue/all.htm
    // Polynomial uses the normal representation, omitting the implicit x^Width term.
    internal static readonly CrcPreset[] Presets =
    [
        new("CRC-3/GSM", new(3, 0x3, 0, false, false, 0x7), 0x4),
        new("CRC-4/G-704", new(4, 0x3, 0, true, true, 0), 0x7),
        new("CRC-5/USB", new(5, 0x05, 0x1F, true, true, 0x1F), 0x19),
        new("CRC-7/MMC", new(7, 0x09, 0, false, false, 0), 0x75),
        new("CRC-8/AUTOSAR", new(8, 0x2F, 0xFF, false, false, 0xFF), 0xDF),
        new("CRC-8/MAXIM-DOW", new(8, 0x31, 0, true, true, 0), 0xA1),
        new("CRC-8/SAE-J1850", new(8, 0x1D, 0xFF, false, false, 0xFF), 0x4B),
        new("CRC-8/SMBUS", new(8, 0x07, 0, false, false, 0), 0xF4),
        new("CRC-12/UMTS", new(12, 0x80F, 0, false, true, 0), 0xDAF),
        new("CRC-15/CAN", new(15, 0x4599, 0, false, false, 0), 0x059E),
        new("CRC-16/ARC", new(16, 0x8005, 0, true, true, 0), 0xBB3D),
        new("CRC-16/DNP", new(16, 0x3D65, 0, true, true, 0xFFFF), 0xEA82),
        new("CRC-16/IBM-3740", new(16, 0x1021, 0xFFFF, false, false, 0), 0x29B1),
        new("CRC-16/IBM-SDLC", new(16, 0x1021, 0xFFFF, true, true, 0xFFFF), 0x906E),
        new("CRC-16/KERMIT", new(16, 0x1021, 0, true, true, 0), 0x2189),
        new("CRC-16/MODBUS", new(16, 0x8005, 0xFFFF, true, true, 0), 0x4B37),
        new("CRC-16/SPI-FUJITSU", new(16, 0x1021, 0x1D0F, false, false, 0), 0xE5CC),
        new("CRC-16/USB", new(16, 0x8005, 0xFFFF, true, true, 0xFFFF), 0xB4C8),
        new("CRC-16/XMODEM", new(16, 0x1021, 0, false, false, 0), 0x31C3),
        new("CRC-24/BLE", new(24, 0x00065B, 0x555555, true, true, 0), 0xC25A56),
        new("CRC-24/OPENPGP", new(24, 0x864CFB, 0xB704CE, false, false, 0), 0x21CF02),
        new("CRC-32/AUTOSAR", new(32, 0xF4ACFB13, 0xFFFFFFFF, true, true, 0xFFFFFFFF), 0x1697D06A),
        new("CRC-32/BZIP2", new(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF), 0xFC891918),
        new("CRC-32/CKSUM", new(32, 0x04C11DB7, 0, false, false, 0xFFFFFFFF), 0x765E7680),
        new("CRC-32/ISCSI", new(32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF), 0xE3069283),
        new("CRC-32/ISO-HDLC", new(32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF), 0xCBF43926),
        new("CRC-32/JAMCRC", new(32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0), 0x340BC6D9),
        new("CRC-32/MPEG-2", new(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0), 0x0376E6E7),
        new("CRC-64/ECMA-182", new(64, 0x42F0E1EBA9EA3693, 0, false, false, 0), 0x6C40DF5F0B497347),
        new("CRC-64/GO-ISO", new(64, 0x1B, ulong.MaxValue, true, true, ulong.MaxValue), 0xB90956C775A41001),
        new("CRC-64/WE", new(64, 0x42F0E1EBA9EA3693, ulong.MaxValue, false, false, ulong.MaxValue), 0x62EC59E3F1A4F00A),
        new("CRC-64/XZ", new(64, 0x42F0E1EBA9EA3693, ulong.MaxValue, true, true, ulong.MaxValue), 0x995DC9BBDF1939FA)
    ];

    internal static ulong Compute(ReadOnlySpan<byte> data, CrcParameters parameters)
    {
        ulong mask = Validate(parameters);
        ulong crc = Update(data, parameters.Initial, parameters, mask);
        return FinalizeCrc(crc, parameters, mask);
    }

    internal static async ValueTask<ulong> ComputeAsync(
        Stream data,
        CrcParameters parameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ulong mask = Validate(parameters);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] buffer = new byte[64 * 1024];
        ulong crc = parameters.Initial;
        while (true)
        {
            int count = await data.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (count == 0)
                return FinalizeCrc(crc, parameters, mask);
            crc = Update(buffer.AsSpan(0, count), crc, parameters, mask);
        }
    }

    private static ulong Validate(CrcParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ulong mask = Mask(parameters.Width);
        if (parameters.Polynomial == 0 ||
            (parameters.Polynomial & mask) != parameters.Polynomial ||
            (parameters.Initial & mask) != parameters.Initial ||
            (parameters.XorOut & mask) != parameters.XorOut)
            throw new ArgumentException(L("InvalidCrcParameters"), nameof(parameters));
        return mask;
    }

    private static ulong Update(ReadOnlySpan<byte> data, ulong crc, CrcParameters parameters, ulong mask)
    {
        ulong highBit = 1UL << (parameters.Width - 1);
        foreach (byte value in data)
        {
            // Read the byte in the model's input bit order. Keeping the register in
            // normal order also handles widths below eight without special shifts.
            for (int bit = 0; bit < 8; bit++)
            {
                int inputBit = parameters.ReflectInput ? bit : 7 - bit;
                bool feedback = ((crc & highBit) != 0) ^ ((value & (1 << inputBit)) != 0);
                crc = (crc << 1) & mask;
                if (feedback)
                    crc ^= parameters.Polynomial;
            }
        }
        return crc;
    }

    private static ulong FinalizeCrc(ulong crc, CrcParameters parameters, ulong mask)
    {
        if (parameters.ReflectOutput)
            crc = Reflect(crc, parameters.Width);
        return (crc ^ parameters.XorOut) & mask;
    }

    internal static ulong ParseHex(string value, int width)
    {
        ArgumentNullException.ThrowIfNull(value);
        ulong mask = Mask(width);
        string text = string.Concat(value.Where(character => !char.IsWhiteSpace(character)));
        ReadOnlySpan<char> digits = text.AsSpan();
        if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            digits = digits[2..];
        if (digits.IsEmpty)
            throw new ArgumentException(L("InvalidCrcHex"), nameof(value));

        ulong result = 0;
        foreach (char character in digits)
        {
            int digit = character switch
            {
                >= '0' and <= '9' => character - '0',
                >= 'a' and <= 'f' => character - 'a' + 10,
                >= 'A' and <= 'F' => character - 'A' + 10,
                _ => -1
            };
            if (digit < 0 || (ulong)digit > mask || result > (mask - (ulong)digit) / 16)
                throw new ArgumentException(L("InvalidCrcHex"), nameof(value));
            result = result * 16 + (ulong)digit;
        }
        return result;
    }

    internal static string FormatHex(ulong value, int width)
    {
        ulong mask = Mask(width);
        if ((value & mask) != value)
            throw new ArgumentException(L("InvalidCrcParameters"), nameof(value));
        return value.ToString("X" + ((width + 3) / 4).ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
    }

    private static ulong Mask(int width)
    {
        if (width is < 1 or > 64)
            throw new ArgumentException(L("InvalidCrcParameters"), nameof(width));
        return width == 64 ? ulong.MaxValue : (1UL << width) - 1;
    }

    private static ulong Reflect(ulong value, int width)
    {
        ulong reflected = 0;
        for (int bit = 0; bit < width; bit++)
        {
            reflected = (reflected << 1) | (value & 1);
            value >>= 1;
        }
        return reflected;
    }
}
