namespace JPKGReader;

public class Program
{
    private static List<Func<Stream, JPKG>> _versions;
    static Program()
    {
        _versions = [
            stream => new JPKGV1(stream),
            stream => new JPKGV4(stream)
        ];
    }
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

        JPKG pkg;
        using var fs = File.OpenRead(args[0]);
        Stream fsContents;
        if (File.Exists(args[0] + "_contents"))
            fsContents = File.OpenRead(args[0] + "_contents");
        else fsContents = new MemoryStream();
        
        foreach (var version in _versions)
        {
            try
            {
                pkg = version(fs);
                pkg.Parse();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while parsing {nameof(pkg)}, {ex}");
            }

            fs.Position = 0;
        }
        
        try
        {
            pkg = new JPKGV3(fs, fsContents);
            pkg.Parse();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error while parsing {nameof(pkg)}, {ex}");
        }

        fs.Position = 0;
    }
}