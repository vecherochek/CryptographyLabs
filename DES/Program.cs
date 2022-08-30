using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using CipherContext;

namespace DES
{
    static class Program
    {
        static async Task Main(string[] args)
        {
            ulong a = 0x1234567890abcdef;
            byte[] key = BitConverter.GetBytes(a);

            var q = new CipherContext.CipherContext(key, new byte[] {1, 1, 1, 0, 1, 1, 1, 1}, "kek");

            q.Encoder = new DES();
            q.EncryptionMode = EncryptionModeList.ECB;
            q.EncryptionMode = EncryptionModeList.CBC;
            q.EncryptionMode = EncryptionModeList.CFB;
            q.EncryptionMode = EncryptionModeList.CTR;
            q.EncryptionMode = EncryptionModeList.OFB;
            q.EncryptionMode = EncryptionModeList.RD;
            q.EncryptionMode = EncryptionModeList.RDH;
            
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
            //Console.WriteLine($"Файл размером {bytes.Length} байт" + Environment.NewLine);

            stopwatch.Start();
            var encryptedBytes = await q.Encrypt(bytes, keys);
            //stopwatch.Stop();
            //Console.WriteLine($"Время шифр: {stopwatch.Elapsed.TotalSeconds} сек");
            //stopwatch.Reset();

            await File.WriteAllBytesAsync(encryptedPath, encryptedBytes);

            var bytes2 = File.ReadAllBytesAsync(encryptedPath);

            ////stopwatch.Start();
            var decryptedBytes = q.Decrypt(await bytes2, keys);
            await File.WriteAllBytesAsync(decryptedPath, await decryptedBytes);

            stopwatch.Stop();
            Console.WriteLine($"Время: {stopwatch.Elapsed.TotalSeconds} сек");
        }
    }
}