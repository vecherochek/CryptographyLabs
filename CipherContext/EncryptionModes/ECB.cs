using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using SymmetricalAlgorithm;

namespace CipherContext.EncryptionModes
{
    internal class ECB
    {
        private ISymmetricalAlgorithm _encoder;
        
        public ECB(ISymmetricalAlgorithm encryptor)
        {
            _encoder = encryptor;
        }
        
        public byte[] EncryptBlock(byte[] message, byte[][] roundKeys)
        {
            var tasks = new List<Task<byte[]>>();
            for (var i = 0; i < message.Length / _encoder.BlockSize; i++)
            {
                var i1 = i;
                tasks.Add(Task.Run(() =>
                {
                    var currentBlock = message.Skip(i1 * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                    return _encoder.Encrypt(currentBlock, roundKeys);
                }));
            }
            var result =  Task.WhenAll(tasks);
            
            return result.Result.SelectMany(block => block).ToArray();
        }
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys)
        {

            var tasks = new List<Task<byte[]>>();
            for (var i = 0; i < message.Length / _encoder.BlockSize; i++)
            {
                var i1 = i;
                tasks.Add(new Task<byte[]>(() =>
                {
                    var currentBlock = message.Skip(i1 * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                    return _encoder.Decrypt(currentBlock, roundKeys);
                }));
                tasks[i].Start();
            }
            var decrypted =  Task.WhenAll(tasks);
            var result = decrypted.Result.SelectMany(block => block).ToArray();
            Array.Resize(ref result, message.Length - result[^1]);

            return result;
        }
    }
}