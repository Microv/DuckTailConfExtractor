using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Dynamic;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.IO;


public class Profile
{
    public string k { get; set; }
    public string v { get; set; }
}
class DuckTailConfExtractor
{
    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: DuckTailConfExtractor <profileFilePath>");
            return;
        }

        string filePath = args[0];
        // Check if the file exists
        if (!File.Exists(filePath))
        {
            Console.WriteLine("File not found.");
            return;
        }

        // Read the JSON file
        string jsonContent = File.ReadAllText(filePath);

        // Deserialize the JSON content into a Profile object
        Profile p = System.Text.Json.JsonSerializer.Deserialize<Profile>(jsonContent);

        // Get Key and Value to decrypt
        string k = p.k;
        string input = p.v;


        // Decode and decrypt values
        byte[] keys = Convert.FromBase64String(k);    
        byte[] array = Convert.FromBase64String(input);
        CbcBlockCipher cbcBlockCipher = new CbcBlockCipher(new AesEngine());
        PaddedBufferedBlockCipher paddedBufferedBlockCipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new Pkcs7Padding());
        byte[] array2 = array.Take(cbcBlockCipher.GetBlockSize()).ToArray<byte>();
        byte[] array3 = array.Skip(cbcBlockCipher.GetBlockSize()).ToArray<byte>();
        ParametersWithIV parametersWithIV = new ParametersWithIV(new KeyParameter(keys), array2, 0, cbcBlockCipher.GetBlockSize());
        paddedBufferedBlockCipher.Init(false, parametersWithIV);
        byte[] array4 = new byte[paddedBufferedBlockCipher.GetOutputSize(array3.Length)];
        int num = paddedBufferedBlockCipher.ProcessBytes(array3, array4, 0);
        num += paddedBufferedBlockCipher.DoFinal(array4, num);
        Console.WriteLine(Encoding.UTF8.GetString(array4, 0, num));
    }
}


