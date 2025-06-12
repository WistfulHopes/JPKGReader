using System.Runtime.InteropServices;

namespace JPKGReader;
public class XORShift32
{
    private uint _state;

    public XORShift32(uint seed)
    {
        _state = seed;
    }

    public uint Next()
    {
        _state ^= _state << 13;
        _state ^= _state >> 17;
        _state ^= _state << 5;
        return _state;
    }

    public static void Decrypt(Span<byte> bytes, uint seed)
    {
        var s32 = new XORShift32(seed);

        var buffer = MemoryMarshal.Cast<byte, uint>(bytes);
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] ^= s32.Next();
        }
    }
}
