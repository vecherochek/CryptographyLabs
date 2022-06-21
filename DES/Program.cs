using System;
using System.Numerics;
using System.Text;

namespace DES
{
    class Program
    {
        static void Main(string[] args)
        {
            ulong a =  0x1234567890abcdef;
            
            string b = "кек-908ьл87о6и7гр5мпн6еакеапнр7го8л90щ8ш67гн64е53ке6н7гшщ0978ттт8тг88г78гго67нг5756н";
            
            byte[] key = BitConverter.GetBytes(a);
            
            byte[] block = Encoding.Default.GetBytes(b);

            var q = new CipherContext(key, EncryptionMode.ECB);
            q.Encoder = new DES();
            var keys = q.GenerateRoundKeys();

            var en = q.Encrypt(block, keys);
            var dec = q.Decrypt(en, keys);
            Console.WriteLine(Encoding.Default.GetString(dec));

        }
    }
}