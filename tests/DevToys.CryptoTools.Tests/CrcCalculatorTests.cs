using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class CrcCalculatorTests
{
    public static IEnumerable<object[]> PresetNames =>
        CrcCalculator.Presets.Select(preset => new object[] { preset.Name });

    public static IEnumerable<object[]> StreamPresetCases =>
        CrcCalculator.Presets.SelectMany(preset => new[] { 1, 2, 4, 65536 }
            .Select(chunkSize => new object[] { preset.Name, chunkSize }));

    [Theory]
    [MemberData(nameof(PresetNames))]
    public void PresetsMatchPublishedRevEngCheckValues(string name)
    {
        CrcPreset preset = Assert.Single(CrcCalculator.Presets, item => item.Name == name);
        Assert.Equal(preset.Check, CrcCalculator.Compute("123456789"u8, preset.Parameters));
    }

    [Theory]
    [MemberData(nameof(StreamPresetCases))]
    public async Task StreamingPresetsMatchPublishedCheckAcrossShortReads(string name, int chunkSize)
    {
        CrcPreset preset = Assert.Single(CrcCalculator.Presets, item => item.Name == name);
        using var stream = new ChunkedReadStream("123456789"u8.ToArray(), chunkSize);
        Assert.Equal(preset.Check, await CrcCalculator.ComputeAsync(stream, preset.Parameters));
        Assert.False(stream.IsDisposed);
        Assert.True(stream.ReadCalls >= 2);
    }

    [Theory]
    [InlineData(4093)]
    [InlineData(16384)]
    [InlineData(262144)]
    public async Task StreamingProcessesMultipleBoundedBlocksWithoutSeeking(int chunkSize)
    {
        byte[] data = Enumerable.Range(0, 128 * 1024 + 17).Select(index => (byte)(index % 251)).ToArray();
        foreach (string name in new[] { "CRC-3/GSM", "CRC-12/UMTS", "CRC-64/XZ" })
        {
            CrcPreset preset = Assert.Single(CrcCalculator.Presets, item => item.Name == name);
            using var stream = new ChunkedReadStream(data, chunkSize);
            Assert.Equal(CrcCalculator.Compute(data, preset.Parameters), await CrcCalculator.ComputeAsync(stream, preset.Parameters));
            Assert.True(stream.ReadCalls > 2);
            Assert.InRange(stream.LargestReadRequest, 1, 64 * 1024);
            Assert.False(stream.IsDisposed);
        }
    }

    [Fact]
    public async Task StreamingBeginsAtTheCurrentPositionAndLeavesTheStreamOpen()
    {
        CrcPreset preset = Assert.Single(CrcCalculator.Presets, item => item.Name == "CRC-32/ISO-HDLC");
        using var stream = new MemoryStream("skip123456789"u8.ToArray());
        stream.Position = 4;
        Assert.Equal(0xCBF43926UL, await CrcCalculator.ComputeAsync(stream, preset.Parameters));
        Assert.True(stream.CanRead);
        Assert.Equal(stream.Length, stream.Position);
    }

    [Fact]
    public async Task EmptyStreamAppliesInitialReflectionAndFinalXor()
    {
        using var stream = new ChunkedReadStream([], 1);
        Assert.Equal(0xEDUL, await CrcCalculator.ComputeAsync(stream, new(8, 7, 0x12, true, true, 0xA5)));
        Assert.False(stream.IsDisposed);
    }

    [Fact]
    public async Task StreamingHonorsCancellationBeforeReading()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        using var stream = new ChunkedReadStream([1, 2, 3], 1);
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await CrcCalculator.ComputeAsync(stream, new(8, 7, 0, false, false, 0), cancellation.Token));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        Assert.Equal(0, stream.ReadCalls);
        Assert.False(stream.IsDisposed);
    }

    [Fact]
    public async Task StreamingHonorsCancellationAfterAReadEvenIfTheStreamDoesNotThrow()
    {
        using var cancellation = new CancellationTokenSource();
        using var stream = new ChunkedReadStream([1, 2, 3], 1, afterRead: cancellation.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await CrcCalculator.ComputeAsync(stream, new(8, 7, 0, false, false, 0), cancellation.Token));
        Assert.Equal(1, stream.ReadCalls);
        Assert.False(stream.IsDisposed);
    }

    [Fact]
    public async Task StreamingPropagatesReadFailuresWithoutClosingTheStream()
    {
        var failure = new IOException("Read failed.");
        using var stream = new ChunkedReadStream([1, 2, 3], 1, failure: failure);
        var error = await Assert.ThrowsAsync<IOException>(async () =>
            await CrcCalculator.ComputeAsync(stream, new(8, 7, 0, false, false, 0)));
        Assert.Same(failure, error);
        Assert.False(stream.IsDisposed);
    }

    [Fact]
    public void PresetsHaveUniqueNamesAndCoverCommonWidths()
    {
        Assert.Equal(CrcCalculator.Presets.Length, CrcCalculator.Presets.Select(preset => preset.Name).Distinct().Count());
        Assert.Contains(CrcCalculator.Presets, preset => preset.Name == "CRC-32/ISO-HDLC");
        foreach (int width in new[] { 3, 4, 5, 7, 8, 12, 15, 16, 24, 32, 64 })
            Assert.Contains(CrcCalculator.Presets, preset => preset.Parameters.Width == width);
    }

    [Theory]
    [InlineData(false, false, 0xB7UL)]
    [InlineData(true, false, 0xB7UL)]
    [InlineData(false, true, 0xEDUL)]
    [InlineData(true, true, 0xEDUL)]
    public void EmptyInputAppliesInitialOutputReflectionAndFinalXor(bool reflectInput, bool reflectOutput, ulong expected)
    {
        // 0x12 XOR 0xA5 = 0xB7; reflect8(0x12) XOR 0xA5 = 0xED.
        var parameters = new CrcParameters(8, 0x07, 0x12, reflectInput, reflectOutput, 0xA5);
        Assert.Equal(expected, CrcCalculator.Compute([], parameters));
    }

    [Theory]
    [InlineData(false, false, 0x3UL)]
    [InlineData(true, false, 0xCUL)]
    [InlineData(false, true, 0xCUL)]
    [InlineData(true, true, 0x3UL)]
    public void CustomFourBitPolynomialHonorsReflectionIndependently(bool reflectInput, bool reflectOutput, ulong expected)
    {
        // Polynomial division: (0x12 << 4) mod 0x13 = 3;
        // reflecting the input changes 0x12 to 0x48, whose remainder is C.
        var parameters = new CrcParameters(4, 0x3, 0, reflectInput, reflectOutput, 0);
        Assert.Equal(expected, CrcCalculator.Compute([0x12], parameters));
    }

    [Fact]
    public void CustomThreeBitPolynomialProcessesAllEightInputBits()
    {
        // (0x12 << 3) mod 0xB = 7.
        Assert.Equal(7UL, CrcCalculator.Compute([0x12], new(3, 0x3, 0, false, false, 0)));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void OneBitPolynomialComputesParity(bool reflectInput, bool reflectOutput)
    {
        Assert.Equal(1UL, CrcCalculator.Compute([0x80, 0x01, 0x7F], new(1, 1, 0, reflectInput, reflectOutput, 0)));
        Assert.Equal(0UL, CrcCalculator.Compute([0x80, 0x01, 0x7F], new(1, 1, 1, reflectInput, reflectOutput, 0)));
    }

    [Fact]
    public void FullWidthRegisterDiscardsOverflowAndHandlesHighestBit()
    {
        Assert.Equal(1UL, CrcCalculator.Compute([0x02], new(64, ulong.MaxValue, 0, false, false, 0)));
        Assert.Equal(0x80UL, CrcCalculator.Compute([0x00], new(64, 1, 0x8000000000000000, false, false, 0)));
        Assert.Equal(0x0100000000000000UL, CrcCalculator.Compute([0x00], new(64, 1, 0x8000000000000000, false, true, 0)));
    }

    [Fact]
    public void ManualPolynomialCanHaveAZeroConstantTerm()
    {
        // (0x01 << 4) mod 0x12 = 2.
        Assert.Equal(2UL, CrcCalculator.Compute([0x01], new(4, 2, 0, false, false, 0)));
    }

    [Theory]
    [InlineData("0", 1, 0UL)]
    [InlineData(" 0x 1 ", 1, 1UL)]
    [InlineData("0X 0a bC\r\n", 12, 0xABCUL)]
    [InlineData("00000000000000000001", 1, 1UL)]
    [InlineData("FFFFFFFFFFFFFFFF", 64, ulong.MaxValue)]
    public void ParseHexAcceptsWhitespacePrefixAndWidthBoundaries(string text, int width, ulong expected) =>
        Assert.Equal(expected, CrcCalculator.ParseHex(text, width));

    [Theory]
    [InlineData("", 8)]
    [InlineData(" \t\r\n", 8)]
    [InlineData("0x", 8)]
    [InlineData("-1", 8)]
    [InlineData("+1", 8)]
    [InlineData("1_0", 8)]
    [InlineData("0b10", 8)]
    [InlineData("gg", 8)]
    [InlineData("100", 8)]
    [InlineData("8", 3)]
    [InlineData("10000000000000000", 64)]
    public void ParseHexRejectsMalformedOrOutOfWidthValues(string text, int width) =>
        Assert.Throws<ArgumentException>(() => CrcCalculator.ParseHex(text, width));

    [Theory]
    [InlineData(0UL, 1, "0")]
    [InlineData(1UL, 3, "1")]
    [InlineData(1UL, 5, "01")]
    [InlineData(0xABCUL, 12, "ABC")]
    [InlineData(0x59EUL, 15, "059E")]
    [InlineData(0x376E6E7UL, 32, "0376E6E7")]
    [InlineData(1UL, 64, "0000000000000001")]
    [InlineData(ulong.MaxValue, 64, "FFFFFFFFFFFFFFFF")]
    public void FormatHexUsesFixedWidthUppercaseWithoutPrefix(ulong value, int width, string expected) =>
        Assert.Equal(expected, CrcCalculator.FormatHex(value, width));

    [Theory]
    [InlineData(0, 1UL, 0UL, 0UL)]
    [InlineData(-1, 1UL, 0UL, 0UL)]
    [InlineData(65, 1UL, 0UL, 0UL)]
    [InlineData(8, 0UL, 0UL, 0UL)]
    [InlineData(8, 0x107UL, 0UL, 0UL)]
    [InlineData(8, 7UL, 0x100UL, 0UL)]
    [InlineData(8, 7UL, 0UL, 0x100UL)]
    public async Task ComputeMethodsRejectInvalidParametersBeforeReading(int width, ulong polynomial, ulong initial, ulong xorOut)
    {
        var parameters = new CrcParameters(width, polynomial, initial, false, false, xorOut);
        Assert.Throws<ArgumentException>(() => CrcCalculator.Compute([], parameters));
        using var stream = new ChunkedReadStream([1], 1);
        await Assert.ThrowsAsync<ArgumentException>(async () => await CrcCalculator.ComputeAsync(stream, parameters));
        Assert.Equal(0, stream.ReadCalls);
        Assert.False(stream.IsDisposed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    public void HexHelpersRejectInvalidWidths(int width)
    {
        Assert.Throws<ArgumentException>(() => CrcCalculator.ParseHex("0", width));
        Assert.Throws<ArgumentException>(() => CrcCalculator.FormatHex(0, width));
    }

    [Fact]
    public void FormatHexRejectsValueOutsideWidth() =>
        Assert.Throws<ArgumentException>(() => CrcCalculator.FormatHex(0x10, 4));

    [Fact]
    public void NullArgumentsAreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => CrcCalculator.Compute([], null!));
        Assert.Throws<ArgumentNullException>(() => CrcCalculator.ParseHex(null!, 8));
    }

    [Fact]
    public async Task StreamingRejectsNullArguments()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await CrcCalculator.ComputeAsync(null!, new(8, 7, 0, false, false, 0)));
        using var stream = new ChunkedReadStream([1], 1);
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await CrcCalculator.ComputeAsync(stream, null!));
        Assert.Equal(0, stream.ReadCalls);
    }

    private sealed class ChunkedReadStream(byte[] data, int maximumChunkSize, Action? afterRead = null, Exception? failure = null) : Stream
    {
        private int _position;
        internal int ReadCalls { get; private set; }
        internal int LargestReadRequest { get; private set; }
        internal bool IsDisposed { get; private set; }
        public override bool CanRead => !IsDisposed;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCalls++;
            LargestReadRequest = Math.Max(LargestReadRequest, buffer.Length);
            await Task.Yield();
            if (failure is not null)
                throw failure;
            int count = Math.Min(Math.Min(maximumChunkSize, buffer.Length), data.Length - _position);
            data.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            afterRead?.Invoke();
            return count;
        }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
