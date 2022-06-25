using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using CipherContext;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    static class Program
    {
        static async Task Main(string[] args)
        {
            ulong a =  0x1234567890abcdef;
            byte[] key = BitConverter.GetBytes(a);
            
            //var q = new CipherContext.CipherContext(key, EncryptionMode.CFB, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext.CipherContext(key, EncryptionMode.ECB);
            //var q = new CipherContext.CipherContext(key, EncryptionMode.CBC, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext.CipherContext(key, EncryptionMode.OFB, new byte[]{1,1,1,0,1,1,1,1});
            //var q = new CipherContext.CipherContext(key, EncryptionMode.RD, new byte[]{1,1,1,0,1,1,1,1});
            var q = new CipherContext.CipherContext(key, EncryptionMode.RDH, new byte[]{1,1,1,0,1,1,1,1}, "kek");
            //var q = new CipherContext.CipherContext(key, EncryptionMode.CTR, new byte[]{1,1,1,0,1,1,1,1});

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
            if (workingDir == null) return;
            var originPath = Path.Combine(workingDir, origin);
            var encryptedPath = Path.Combine(workingDir, encrypted);
            var decryptedPath = Path.Combine(workingDir, decrypted);
            
            Stopwatch stopwatch = new Stopwatch();
            var bytes = await File.ReadAllBytesAsync(originPath);
            Console.WriteLine($"Файл размером {bytes.Length} байт" + Environment.NewLine);
            
            stopwatch.Start();
            var encryptedBytes = await q.Encrypt(bytes, keys);
            stopwatch.Stop();
            
            Console.WriteLine($"Время шифр: {stopwatch.Elapsed.TotalSeconds} сек");
            stopwatch.Reset();

            await File.WriteAllBytesAsync(encryptedPath, encryptedBytes);
            
            var bytes2 = await File.ReadAllBytesAsync(encryptedPath);
            
            stopwatch.Start();
            var decryptedBytes = await q.Decrypt(bytes2, keys);
            stopwatch.Stop();
            Console.WriteLine($"Время дешифр: {stopwatch.Elapsed.TotalSeconds} сек");
            
            await File.WriteAllBytesAsync(decryptedPath, decryptedBytes);
        }
    }
}