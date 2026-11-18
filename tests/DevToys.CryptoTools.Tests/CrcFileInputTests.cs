using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class CrcFileInputTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(1)]
    [InlineData(0)]
    public async Task DroppedFileUsesOriginalBytesInsteadOfTheManualInputEncoding(int encoding)
    {
        using var tool = new CrcTool();
        Select(tool, "crc-input-encoding", (BinaryEncoding)encoding);
        var file = new MemoryFile("input.bin", "123456789"u8.ToArray());
        await Drop(tool, file);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "crc-input").Text);
        await Calculate(tool);
        Assert.Equal("CBF43926", Result(tool));
        Assert.False(file.IsDisposed);
    }

    [Fact]
    public async Task BinaryFileDoesNotRequireValidUtf8Text()
    {
        using var tool = new CrcTool();
        var file = new MemoryFile("binary.dat", [0x00, 0xFF, 0x80, 0x81, 0xC3, 0x28]);
        await Drop(tool, file);
        await Calculate(tool);
        Assert.Equal("A36A8DD4", Result(tool));
    }

    [Fact]
    public async Task ChangingThePresetReopensTheSameFileForRecalculation()
    {
        using var tool = new CrcTool();
        var file = new MemoryFile("input.bin", "123456789"u8.ToArray());
        await Drop(tool, file);
        await Calculate(tool);
        Assert.Equal("CBF43926", Result(tool));
        Select(tool, "crc-preset", "CRC-16/MODBUS");
        await Calculate(tool);
        Assert.Equal("4B37", Result(tool));
        Assert.Equal(2, file.OpenCount);
        Assert.False(file.IsDisposed);
    }

    [Fact]
    public async Task TypingManualInputReleasesTheFileAndUsesTheSelectedEncoding()
    {
        using var tool = new CrcTool();
        var file = new MemoryFile("input.bin", [0xFF, 0x00]);
        await Drop(tool, file);
        await Calculate(tool);
        Select(tool, "crc-input-encoding", BinaryEncoding.Hex);
        Find<IUIMultiLineTextInput>(tool, "crc-input").Text("31 32 33 34 35 36 37 38 39");
        Assert.True(file.IsDisposed);
        Assert.Empty(Find<IUIFileSelector>(tool, "crc-input-file").SelectedFiles!);
        await Calculate(tool);
        Assert.Equal("CBF43926", Result(tool));
    }

    [Fact]
    public async Task ReplacingAndClearingFilesReleaseReadersAndRecalculateTheCurrentInput()
    {
        using var tool = new CrcTool();
        var first = new MemoryFile("first.bin", "123456789"u8.ToArray());
        var second = new MemoryFile("empty.bin", []);
        await Drop(tool, first);
        await Calculate(tool);
        await Drop(tool, second);
        Assert.True(first.IsDisposed);
        await Calculate(tool);
        Assert.Equal("00000000", Result(tool));
        await Drop(tool);
        Assert.True(second.IsDisposed);
        await Calculate(tool);
        Assert.Equal("00000000", Result(tool));
    }

    [Fact]
    public async Task DisposingTheToolReleasesTheSelectedFileAfterAutomaticCalculation()
    {
        var tool = new CrcTool();
        var file = new MemoryFile("selected.bin", [1, 2, 3]);
        await Drop(tool, file);
        await Calculate(tool);
        tool.Dispose();
        Assert.True(file.IsDisposed);
        Assert.Equal(1, file.OpenCount);
    }

    [Fact]
    public async Task MultipleFilesAreRejectedAndReleasedWithoutKeepingAResult()
    {
        using var tool = new CrcTool();
        await Calculate(tool);
        Assert.NotEmpty(Result(tool));
        var first = new MemoryFile("first.bin", [1]);
        var second = new MemoryFile("second.bin", [2]);
        await Drop(tool, first, second);
        Assert.Empty(Result(tool));
        Assert.True(first.IsDisposed);
        Assert.True(second.IsDisposed);
        Assert.Equal(0, first.OpenCount);
        Assert.Equal(0, second.OpenCount);
    }

    [Fact]
    public async Task FileReadErrorsAreHandledByAutomaticCalculation()
    {
        using var tool = new CrcTool();
        await Calculate(tool);
        var file = new MemoryFile("unreadable.bin", [], failToRead: true);
        await Drop(tool, file);
        await Calculate(tool);
        Assert.Empty(Result(tool));
        Assert.Equal(1, file.OpenCount);
    }

    [Fact]
    public async Task CancelledOlderFileCalculationCannotHideANewerInputError()
    {
        using var tool = new CrcTool();
        Select(tool, "crc-input-encoding", BinaryEncoding.Hex);
        var file = new DelayedFile();
        await Drop(tool, file);
        Task olderCalculation = tool.CalculationTask;
        IUIInfoBar status;
        string? errorDescription;
        try
        {
            await file.OpenRequested.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Find<IUIMultiLineTextInput>(tool, "crc-input").Text("GG");
            await Calculate(tool);
            status = Assert.IsAssignableFrom<IUIGrid>(tool.View.RootElement).Cells!.Select(cell => cell.Child)
                .OfType<IUIInfoBar>().Single(bar => bar.IsVisible);
            errorDescription = status.Description;
            Assert.False(string.IsNullOrWhiteSpace(errorDescription));
            Assert.Empty(Result(tool));
        }
        finally
        {
            file.CompleteOpen();
            await olderCalculation.WaitAsync(TimeSpan.FromSeconds(5));
        }

        Assert.True(status.IsVisible);
        Assert.Equal(errorDescription, status.Description);
        Assert.Empty(Result(tool));
    }

    private static T Find<T>(CrcTool tool, string id) where T : IUIElement =>
        Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));

    private static string Result(CrcTool tool) => Find<IUISingleLineTextInput>(tool, "crc-output").Text;

    private static void Select(CrcTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }

    private static async Task Drop(CrcTool tool, params SandboxedFileReader[] files) =>
        await Find<IUIFileSelector>(tool, "crc-input-file").OnFilesSelectedAction!(files);

    private static async Task Calculate(CrcTool tool) => await tool.CalculationTask;

    private sealed class DelayedFile() : SandboxedFileReader("delayed.bin")
    {
        private readonly TaskCompletionSource _completeOpen = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource OpenRequested { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal void CompleteOpen() => _completeOpen.TrySetResult();

        protected override async ValueTask<Stream> OpenReadFileAsync(CancellationToken cancellationToken)
        {
            OpenRequested.TrySetResult();
            // Simulate a file provider that completes its pending open after cancellation.
            await _completeOpen.Task;
            return new MemoryStream("123456789"u8.ToArray(), writable: false);
        }
    }

    private sealed class MemoryFile : SandboxedFileReader
    {
        private readonly byte[] _content;
        private readonly bool _failToRead;
        internal bool IsDisposed { get; private set; }
        internal int OpenCount { get; private set; }

        internal MemoryFile(string name, byte[] content, bool failToRead = false) : base(name)
        {
            _content = content;
            _failToRead = failToRead;
            Disposed += (_, _) => IsDisposed = true;
        }

        protected override ValueTask<Stream> OpenReadFileAsync(CancellationToken cancellationToken)
        {
            OpenCount++;
            if (_failToRead) throw new IOException("The file cannot be read.");
            return ValueTask.FromResult<Stream>(new MemoryStream(_content, writable: false));
        }
    }
}
