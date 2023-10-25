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
using static System.Net.Mime.MediaTypeNames;


class DuckTailStringDecryptor
{
    static void Main(string[] args)
    {
        string input = args[0];
        //string input = "zxsQt1PhB9iAI/see5v9Vw==.VfC5pgIk9kOGUCGge5WJLLAT5fG6YYs/9X3tz0LvOIEQ+oS5BgL/k0J6yRO8v+Gz";

        string result = ReadStructEncrypted(input);

        Console.WriteLine(result);
    }

    static string AesDecrypt(string input, byte[] keys)
    {
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
        return Encoding.UTF8.GetString(array4, 0, num);
    }

    static string ReadStructEncrypted(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }
        int num = 0;
        char[] array = text.ToCharArray();
        for (int i = 0; i < array.Length; i++)
        {
            if (array[i] == '.')
            {
                num = i;
            }
        }
        string text2 = text.Substring(0, num);
        string text3 = text.Substring(num + 1);
        byte[] array2 = Convert.FromBase64String(text2);
        return AesDecrypt(text3, array2);
    }

}