using K4os.Compression.LZ4;
using System.Buffers;
using System.Text;

namespace JPKGReader;

public record Node(ulong Hash, long Offset, long Size);

public record Entry(long Offset, int Size, int Type);

public record FileV4(ulong Hash, long Offset, long UncompressedSize, long Size);

public class Program
{
    private const int MaxBlockSize = 0x40000;

    public static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("JPKGReader <file>");
            return;
        }

        if (!File.Exists(args[0]))
        {
            Console.WriteLine("File does not exist!");
            return;
        }

        Parse(args[0]);
    }

    public static byte[] Decrypt(in byte[] data)
    {
        var outData = new List<byte>();
        var key = 0x9A44EDF5;

        for (var i = 0; i < data.Length >> 2; i++)
        {
            var tmp = (((key << 13) ^ key) >> 17) ^ (key << 13) ^ key;
            key = (32 * tmp) ^ tmp;
            outData.AddRange(BitConverter.GetBytes((uint)(BitConverter.ToInt32(data, i * 4) ^ key)));
        }

        if (data.Length > outData.Count)
        {
            outData.AddRange(data[(outData.Count - 1) .. ^1]);
        }
        
        return outData.ToArray();
    }

    public static bool CheckEncoding(string value, Encoding encoding)
    {
        bool retCode;
        var charArray = value.ToCharArray();
        byte[] bytes = new byte[charArray.Length];
        for (int i = 0; i < charArray.Length; i++)
        {
            bytes[i] = (byte)charArray[i];
        }

        retCode = string.Equals(encoding.GetString(bytes, 0, bytes.Length), value, StringComparison.InvariantCulture);
        return retCode;
    }

    public static void Parse(string path)
    {
        using var fs = File.OpenRead(path);
        using var encryptReader = new BinaryReader(fs);

        var header = Decrypt(encryptReader.ReadBytes(48));
        using var headerReader = new BinaryReader(new MemoryStream(header));

        var signature = Encoding.UTF8.GetString(headerReader.ReadBytes(4));
        if (signature != "jPKG")
            throw new Exception("Invalid magic! This doesn't look like a jPKG file!");

        var version = headerReader.ReadInt64();

        switch (version)
        {
            case 3:
            {
                var unk0 = headerReader.ReadInt32();
                var filesCount = headerReader.ReadInt32();
                var blocksCount = headerReader.ReadInt32();
                var filesSize = headerReader.ReadInt32();
                var blocksSize = headerReader.ReadInt32();
                var dataOffset = headerReader.ReadInt32();
                var unk1 = headerReader.ReadInt32();
                var size = headerReader.ReadInt32();
                var unk2 = headerReader.ReadInt32();

                var files = new List<Node>();
                var blocks = new List<Entry>();

                var listSize = filesSize + blocksSize;
                var list = Decrypt(encryptReader.ReadBytes(listSize));
                using var listReader = new BinaryReader(new MemoryStream(list));

                while (listReader.BaseStream.Position < filesSize)
                {
                    files.Add(new(listReader.ReadUInt64(), listReader.ReadInt64(), listReader.ReadInt64()));
                }

                if (files.Count != filesCount)
                {
                    throw new IOException($"Expected {filesCount} files, got {files.Count} instead!");
                }

                var pos = listReader.BaseStream.Position;

                while (listReader.BaseStream.Position - pos < blocksSize)
                {
                    blocks.Add(new(listReader.ReadInt64(), listReader.ReadInt32(), listReader.ReadInt32()));
                }

                if (blocks.Count != blocksCount)
                {
                    throw new IOException($"Expected {blocksCount} blocks, got {blocks.Count} instead!");
                }

                using MemoryStream blocksStream = new();
                var encryptedBuffer = ArrayPool<byte>.Shared.Rent(MaxBlockSize);
                var decompressedBuffer = ArrayPool<byte>.Shared.Rent(MaxBlockSize);
                try
                {
                    foreach (var block in blocks)
                    {
                        encryptReader.BaseStream.Position = block.Offset;
                        encryptReader.Read(encryptedBuffer, 0, block.Size);
                        var compressedBuffer = Decrypt(encryptedBuffer);

                        if (block.Size == MaxBlockSize)
                        {
                            blocksStream.Write(compressedBuffer, 0, block.Size);
                        }
                        else
                        {
                            var numWrite = LZ4Codec.Decode(compressedBuffer.AsSpan(0, block.Size),
                                decompressedBuffer.AsSpan(0, MaxBlockSize));
                            if (numWrite == -1)
                            {
                                throw new IOException(
                                    $"Lz4 decompression error, write {numWrite} bytes but expected {MaxBlockSize} bytes");
                            }

                            blocksStream.Write(decompressedBuffer, 0, numWrite);
                        }
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(encryptedBuffer);
                    ArrayPool<byte>.Shared.Return(decompressedBuffer);
                }

                using BinaryReader blocksReader = new(blocksStream);
                blocksReader.BaseStream.Position = 0;

                var folderName = Path.GetFileNameWithoutExtension(path);
                Directory.CreateDirectory($"output/{folderName}");

                foreach (var file in files)
                {
                    blocksReader.BaseStream.Position = file.Offset;
                    byte[] data = blocksReader.ReadBytes((int)file.Size);

                    var fileName = $"{file.Hash:X8}." + Encoding.UTF8.GetString(data[..4]) switch
                    {
                        "OggS" => "ogg",
                        "jTOC" => "jtoc",
                        "jARC" => "jarc",
                        "jLUA" => "jlua",
                        "jlev" => "jlev",
                        "jpfb" => "jpfb",
                        "jMSG" => "jmsg",
                        "coli" => "coli",
                        "soli" => "soli",
                        "jtex" => "jtex",
                        "jmo2" => "jmo2",
                        "OTTO" => "otto",
                        "jSHD" => "jshd",
                        "jprj" => "jprj",
                        "BKHD" => "bnk",
                        "jIDT" => "jidt",
                        "jTXS" => "jtxs",
                        "jSDF" => "jsdf",
                        "jfxc" => "jfxc",
                        "jvfx" => "jvfx",
                        "mesh" => "mesh",
                        "skel" => "skel",
                        "jSWD" => "jswd",
                        "jSCR" => "jscr",
                        _ => "dat"
                    };

                    if (fileName.EndsWith("dat") && CheckEncoding(Encoding.UTF8.GetString(data[..4]), Encoding.UTF8))
                    {
                        Console.WriteLine("Unknown magic in file " + fileName + ": " +
                                          Encoding.UTF8.GetString(data[..4]));
                    }

                    File.WriteAllBytes($"output/{folderName}/{fileName}", data);
                }

                Console.WriteLine("Done!");
                break;
            }
            case 4:
            {
                var unk0 = headerReader.ReadInt64();
                var filesCount = headerReader.ReadInt32();
                var filesSize = headerReader.ReadInt32();
                var dataOffset = headerReader.ReadInt32();
                var unk1 = headerReader.ReadInt32();
                var unk2 = headerReader.ReadInt32();
                var size = headerReader.ReadInt32();
                var unk3 = headerReader.ReadInt32();

                var files = new List<FileV4>();

                var list = Decrypt(encryptReader.ReadBytes(filesSize));
                using var listReader = new BinaryReader(new MemoryStream(list));

                while (listReader.BaseStream.Position < filesSize)
                {
                    files.Add(new(listReader.ReadUInt64(), listReader.ReadInt64(), listReader.ReadInt64(),
                        listReader.ReadInt64()));
                }

                if (files.Count != filesCount)
                {
                    throw new IOException($"Expected {filesCount} files, got {files.Count} instead!");
                }

                var folderName = Path.GetFileNameWithoutExtension(path);
                Directory.CreateDirectory($"output/{folderName}");

                foreach (var file in files)
                {
                    var encryptedBuffer = new byte[file.Size];
                    encryptReader.BaseStream.Position = file.Offset;
                    encryptReader.Read(encryptedBuffer, 0, (int)file.Size);
                    var compressedBuffer = Decrypt(encryptedBuffer);
                    var decompressedBuffer = new byte[file.UncompressedSize];

                    if (file.UncompressedSize == file.Size) decompressedBuffer = compressedBuffer;

                    else
                    {
                        var numWrite = LZ4Codec.Decode(compressedBuffer.AsSpan(0, (int)file.Size),
                            decompressedBuffer.AsSpan(0, (int)file.UncompressedSize));
                        if (numWrite == -1)
                        {
                            throw new IOException(
                                $"Lz4 decompression error, write {numWrite} bytes but expected {file.UncompressedSize} bytes");
                        }
                    }
                    
                    var fileName = $"{file.Hash:X8}." + Encoding.UTF8.GetString(decompressedBuffer[..4]) switch
                    {
                        "OggS" => "ogg",
                        "jTOC" => "jtoc",
                        "jARC" => "jarc",
                        "jLUA" => "jlua",
                        "jlev" => "jlev",
                        "jpfb" => "jpfb",
                        "jMSG" => "jmsg",
                        "coli" => "coli",
                        "soli" => "soli",
                        "jtex" => "jtex",
                        "jmo2" => "jmo2",
                        "OTTO" => "otto",
                        "jSHD" => "jshd",
                        "jprj" => "jprj",
                        "BKHD" => "bnk",
                        "jIDT" => "jidt",
                        "jTXS" => "jtxs",
                        "jSDF" => "jsdf",
                        "jfxc" => "jfxc",
                        "jvfx" => "jvfx",
                        "mesh" => "mesh",
                        "skel" => "skel",
                        "jSWD" => "jswd",
                        "jSCR" => "jscr",
                        _ => "dat"
                    };

                    if (fileName.EndsWith("dat") &&
                        CheckEncoding(Encoding.UTF8.GetString(decompressedBuffer[..4]), Encoding.UTF8))
                    {
                        Console.WriteLine("Unknown magic in file " + fileName + ": " +
                                          Encoding.UTF8.GetString(decompressedBuffer[..4]));
                    }

                    File.WriteAllBytes($"output/{folderName}/{fileName}", decompressedBuffer);
                }

                Console.WriteLine("Done!");
                break;
            }
            default:
                throw new Exception($"Version {version} is not supported!");
        }
    }
}