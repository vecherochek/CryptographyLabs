using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Text;
using CipherContext;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    class Program
    {
        static void Main(string[] args)
        {
            ulong a =  0x1234567890abcdef;
            
            //string b = "кек-908ьл87о6и7гр5мпн6еакеапнр7го8л90щ8ш67гн64е53ке6н7гшщ0978ттт8тг88г78гго67нг5756н";
            string b = "кек";
            byte[] key = BitConverter.GetBytes(a);
            byte[] block = Encoding.Default.GetBytes(b);
            //var q = new CipherContext.CipherContext(key, EncryptionMode.CFB, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext.CipherContext(key, EncryptionMode.ECB);
            //var q = new CipherContext.CipherContext(key, EncryptionMode.CBC, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext.CipherContext(key, EncryptionMode.OFB, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext(key, EncryptionMode.RD, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext.CipherContext(key, EncryptionMode.RDH, new byte[]{1,1,1,0,1,1,1,1}, new byte[]{1,3,1,0,1,1,1,254});
            var q = new CipherContext.CipherContext(key, EncryptionMode.CTR, new byte[]{1,1,1,0,1,1,1,1});
            q.Encoder = new DES();
            var keys = q.GenerateRoundKeys();
            
            const string origin = "testing.txt";
            const string encrypted = "encrypted.txt";
            const string decrypted = "decrypted.txt";
            /*const string origin = "test.jpg";
            const string encrypted = "encrypted.jpg";
            const string decrypted = "decrypted.jpg";*/
            /*const string origin = "test.mp4";
            const string encrypted = "encrypted.mp4";
            const string decrypted = "decrypted.mp4";*/
            var workingDir = Directory.GetParent(Environment.CurrentDirectory)?.Parent?.Parent?.FullName;
            if (workingDir == null)
                return;
            var originPath = Path.Combine(workingDir, origin);
            var encryptedPath = Path.Combine(workingDir, encrypted);
            var decryptedPath = Path.Combine(workingDir, decrypted);
            
            Stopwatch stopwatch = new Stopwatch();
            var bytes = File.ReadAllBytes(originPath);
            stopwatch.Start();
            var encryptedBytes = q.Encrypt(bytes, keys);
            stopwatch.Stop();
            Console.WriteLine(bytes.Length + " байт");
            Console.WriteLine("Время шифр: "+ stopwatch.Elapsed.TotalSeconds + " сек");
            
            File.WriteAllBytes(encryptedPath, encryptedBytes);
            
            var bytes2 = File.ReadAllBytes(encryptedPath);
            var decryptedBytes = q.Decrypt(bytes2, keys);
            File.WriteAllBytes(decryptedPath, decryptedBytes);
            
            /*var en = q.Encrypt(block, keys);
            var dec = q.Decrypt(en, keys);
            Console.WriteLine(Encoding.Default.GetString(dec));*/
        }
    }
}