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
            
            string b = "кек65";
            
            byte[] key = BitConverter.GetBytes(a);
            
            byte[] block = Encoding.Default.GetBytes(b);

            var q = new CipherContext(key, EncryptionMode.ECB);
            q.Encrypter = new DES();
            var keys = q.GenerateRoundKeys();
            var t = new BigInteger(keys[0]);
            var en = q.Encrypt(block, keys);
            Console.WriteLine(new BigInteger(en));
            var dec = q.Decrypt(block, keys);
            Console.WriteLine(Encoding.Default.GetString(dec)); 

        }
    }
}