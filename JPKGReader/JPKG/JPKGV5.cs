using K4os.Compression.LZ4;
using System.Buffers;
using System.Text;

namespace JPKGReader;
public class JPKGV5 : JPKG
{
    private const uint Seed = 0x9A44EDF5;
    public long Version { get; set; }
    public long Size { get; set; }
    public List<Node> Files { get; set; } = [];

    public JPKGV5(Stream stream, Stream? contentsStream = null) : base(stream, contentsStream) { }

    public override void Parse()
    {
        ReadHeader();
        ReadFiles();
        ProcessFiles();
    }

    private void ReadHeader()
    {
        byte[] buffer = new byte[0x48];
        Reader.Read(buffer);
        XORShift32.Decrypt(buffer, Seed);
        
        using MemoryStream ms = new(buffer);
        using BinaryReader reader = new(ms);
        var signature = Encoding.UTF8.GetString(reader.ReadBytes(4));
        if (signature != "jPKH")
            throw new Exception("Invalid signature!");

        Version = reader.ReadInt32();
        _ = reader.ReadInt64();
        _ = reader.ReadInt64();
        _ = reader.ReadInt64();
        _ = reader.ReadInt64();
        Size = reader.ReadInt64();

        if (Version != 5)
        {
            throw new Exception($"Expected version 5, got {Version} instead, not supported!");
        }
    }

    private void ReadFiles()
    {
        byte[] buffer = new byte[Size - 40];
        Reader.Read(buffer);
        XORShift32.Decrypt(buffer, Seed);

        using MemoryStream ms = new(buffer);
        using BinaryReader reader = new(ms);
        while (reader.BaseStream.Position < buffer.Length)
        {
            Files.Add(new(reader.ReadUInt64(), reader.ReadInt64(), reader.ReadInt32(), reader.ReadInt32(), reader.ReadUInt64()));
        }
    }

    private void ProcessFiles()
    {
        Directory.CreateDirectory($"output");

        Console.WriteLine("File Count: " + Files.Count);
        for (int i = 0; i < Files.Count - 1; i++)
        {
            var file = Files[i];
            try
            {
                byte[] compressedBuffer = ArrayPool<byte>.Shared.Rent((int)file.CompressedSize);
                byte[] decompressedBuffer = ArrayPool<byte>.Shared.Rent((int)file.DecompressedSize);
                try
                {
                    ContentsReader.BaseStream.Position = file.Offset;
                    ContentsReader.Read(compressedBuffer, 0, (int)file.CompressedSize);

                    XORShift32.Decrypt(compressedBuffer.AsSpan(0, (int)file.CompressedSize), Seed);

                    Span<byte> data;
                    if (file.CompressedSize == file.DecompressedSize)
                    {
                        data = compressedBuffer.AsSpan(0, (int)file.CompressedSize);
                    }
                    else
                    {
                        var numWrite = LZ4Codec.Decode(compressedBuffer.AsSpan(0, (int)file.CompressedSize), decompressedBuffer.AsSpan(0, (int)file.DecompressedSize));
                        if (numWrite == -1)
                        {
                            throw new IOException($"Lz4 decompression error, write {numWrite} bytes but expected {(int)file.DecompressedSize} bytes");
                        }

                        data = decompressedBuffer.AsSpan(0, (int)file.DecompressedSize);
                    }

                    var fileName = $"{file.ID:X16}." + (Extensions.GetValueOrDefault(Encoding.UTF8.GetString(data[..4]), "dat"));

                    Console.WriteLine($"Writing {fileName}");
                    File.WriteAllBytes($"output/{fileName}", data.ToArray());
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(compressedBuffer);
                    ArrayPool<byte>.Shared.Return(decompressedBuffer);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while parsing {nameof(file.ID)}, {ex}");
            }
        }
    }

    public record Node(ulong ID, long Offset, int DecompressedSize, int CompressedSize, ulong Padding);
}
