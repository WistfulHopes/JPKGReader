using K4os.Compression.LZ4;
using System.Buffers;
using System.Text;

namespace JPKGReader;
public class JPKGV1 : JPKG
{
    private const int MaxBlockSize = 0x40000;

    public int FilesCount { get; set; }
    public int BlocksCount { get; set; }
    public int FilesSize { get; set; }
    public int BlocksSize { get; set; }
    public int DataOffset { get; set; }
    public long Version { get; set; }
    public long Size { get; set; }
    public List<Node> Files { get; set; } = [];
    public List<Entry> Blocks { get; set; } = [];

    public JPKGV1(Stream stream) : base(stream) { }

    public override void Parse()
    {
        ReadHeader();

        ReadFiles();
        ReadBlocks();

        using MemoryStream blocksStream = new();
        ProcessBlocks(blocksStream);
        ProcessFiles(blocksStream);
    }

    private void ReadHeader()
    {
        var signature = Encoding.UTF8.GetString(Reader.ReadBytes(4));
        if (signature != "jPKG")
            throw new Exception("Invalid signature!");

        FilesCount = Reader.ReadInt32();
        BlocksCount = Reader.ReadInt32();
        FilesSize = Reader.ReadInt32();
        BlocksSize = Reader.ReadInt32();
        DataOffset = Reader.ReadInt32();
        Version = Reader.ReadInt64();
        Size = Reader.ReadInt64();

        if (Version != 1)
        {
            throw new Exception($"Expected version 1, got {Version} instead, not supported!");
        }
    }

    private void ReadFiles()
    {
        var pos = Reader.BaseStream.Position;

        while (Reader.BaseStream.Position - pos < FilesSize)
        {
            Files.Add(new(Reader.ReadUInt64(), Reader.ReadInt64(), Reader.ReadInt64()));
        }

        if (Files.Count != FilesCount)
        {
            throw new IOException($"Expected {FilesCount} nodes, got {Files.Count} instead!");
        }
    }

    private void ReadBlocks()
    {
        var pos = Reader.BaseStream.Position;

        while (Reader.BaseStream.Position - pos < BlocksSize)
        {
            Blocks.Add(new(Reader.ReadInt64(), Reader.ReadInt32(), Reader.ReadInt32()));
        }

        if (Blocks.Count != BlocksCount)
        {
            throw new IOException($"Expected {BlocksCount} nodes, got {Blocks.Count} instead!");
        }
    }

    private void ProcessBlocks(Stream stream)
    {
        var compressedBuffer = ArrayPool<byte>.Shared.Rent(MaxBlockSize);
        var decompressedBuffer = ArrayPool<byte>.Shared.Rent(MaxBlockSize);
        try
        {
            foreach (var block in Blocks)
            {
                Reader.BaseStream.Position = block.Offset;
                Reader.Read(compressedBuffer, 0, block.Size);

                if (block.Size == MaxBlockSize)
                {
                    stream.Write(compressedBuffer, 0, block.Size);
                }
                else
                {
                    var numWrite = LZ4Codec.Decode(compressedBuffer.AsSpan(0, block.Size), decompressedBuffer.AsSpan(0, MaxBlockSize));
                    if (numWrite == -1)
                    {
                        throw new IOException($"Lz4 decompression error, write {numWrite} bytes but expected {MaxBlockSize} bytes");
                    }

                    stream.Write(decompressedBuffer, 0, numWrite);
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(compressedBuffer);
            ArrayPool<byte>.Shared.Return(decompressedBuffer);
        }

        stream.Position = 0;
    }

    private void ProcessFiles(Stream stream)
    {
        using BinaryReader reader = new(stream, Encoding.UTF8, true);

        Directory.CreateDirectory($"output");

        foreach (var file in Files)
        {
            reader.BaseStream.Position = file.Offset;
            byte[] data = reader.ReadBytes((int)file.Size);

            var fileName = $"{file.ID:X8}." + (Extensions.TryGetValue(Encoding.UTF8.GetString(data[..4]), out var extension) ? extension : "dat");

            Console.WriteLine($"Writing {fileName}");
            File.WriteAllBytes($"output/{fileName}", data);
        }
    }

    public record Node(ulong ID, long Offset, long Size);
    public record Entry(long Offset, int Size, int Type);
}
