using K4os.Compression.LZ4;
using System.Buffers;
using System.Text;

namespace JPKGReader;
public class JPKGV4 : JPKG
{
    private const int MaxBlockSize = 0x40000;
    private const uint Seed = 0x9A44EDF5;

    public int FilesCount { get; set; }
    public int BlocksCount { get; set; }
    public int FilesSize { get; set; }
    public int BlocksSize { get; set; }
    public int DataOffset { get; set; }
    public long Version { get; set; }
    public long Size { get; set; }
    public List<Node> Files { get; set; } = [];
    public List<Entry> Blocks { get; set; } = [];

    public JPKGV4(Stream stream) : base(stream) { }

    public override void Parse()
    {
        ReadHeader();

        byte[] buffer = new byte[FilesSize + BlocksSize];
        Reader.Read(buffer);
        XORShift32.Decrypt(buffer, Seed);

        using MemoryStream ms = new(buffer);
        using BinaryReader reader = new(ms);
        ReadFiles(reader);
        ReadBlocks(reader);

        using HugeMemoryStream blocksStream = new();
        ProcessBlocks(blocksStream);
        ProcessFiles(blocksStream);
    }

    private void ReadHeader()
    {
        byte[] buffer = new byte[0x30];
        Reader.Read(buffer);
        XORShift32.Decrypt(buffer, Seed);

        using MemoryStream ms = new(buffer);
        using BinaryReader reader = new(ms);
        var signature = Encoding.UTF8.GetString(reader.ReadBytes(4));
        if (signature != "jPKG")
            throw new Exception("Invalid signature!");

        Version = reader.ReadInt32();
        _ = reader.ReadInt32();
        FilesCount = reader.ReadInt32();
        BlocksCount = reader.ReadInt32();
        FilesSize = reader.ReadInt32();
        BlocksSize = reader.ReadInt32();
        DataOffset = reader.ReadInt32();
        _ = reader.ReadInt32();
        Size = reader.ReadInt64();

        if (Version != 4)
        {
            throw new Exception($"Expected version 4, got {Version} instead, not supported!");
        }
    }

    private void ReadFiles(BinaryReader reader)
    {
        while (reader.BaseStream.Position < FilesSize)
        {
            Files.Add(new(reader.ReadUInt64(), reader.ReadInt64(), reader.ReadInt64()));
        }

        if (Files.Count != FilesCount)
        {
            throw new IOException($"Expected {FilesCount} nodes, got {Files.Count} instead!");
        }
    }

    private void ReadBlocks(BinaryReader reader)
    {
        while (reader.BaseStream.Position - FilesSize < BlocksSize)
        {
            Blocks.Add(new(reader.ReadInt64(), reader.ReadInt32(), reader.ReadInt32()));
        }

        if (Blocks.Count != BlocksCount)
        {
            throw new IOException($"Expected {BlocksCount} nodes, got {Blocks.Count} instead !!");
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

                XORShift32.Decrypt(compressedBuffer.AsSpan(0, block.Size), Seed);

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

        for (int i = 0; i < Files.Count; i++)
        {
            var file = Files[i];
            reader.BaseStream.Position = file.Offset;
            byte[] data = reader.ReadBytes((int)file.Size);

            var fileName = $"{i}." + (Extensions.TryGetValue(Encoding.UTF8.GetString(data[..4]), out var extension) ? extension : "dat");

            Console.WriteLine($"Writing {fileName}");
            File.WriteAllBytes($"output/{fileName}", data);
        }
    }

    public record Node(ulong ID, long Offset, long Size);
    public record Entry(long Offset, int Size, int Type);
}
