using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SymmetricalAlgorithm;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace CipherContext.EncryptionModes
{
    internal class RD
    {
        private ISymmetricalAlgorithm _encoder;
        
        public RD(ISymmetricalAlgorithm encryptor)
        {
            _encoder = encryptor;
        }
        
        public byte[] EncryptBlock(byte[] message, byte[][] roundKeys, object[] initializationVector)
        {
            var initial = new byte[_encoder.BlockSize];
            Array.Copy((byte[])initializationVector[0], initial, _encoder.BlockSize);
            
            var initialBlock = _encoder.Encrypt(initial, roundKeys);
            //для дельты всегда берем последние 8 байт вектора инициализации
            var delta = initial.Skip(initial.Length - 8).ToArray();
            //делаем дельту нечетной
            delta[0] |= 0x01;
            
            var tasks = new List<Task<byte[]>>();
            for (var i = 0; i < message.Length / _encoder.BlockSize; i++)
            {
                var i1 = i;
                initial = ByteArrayAdditionByModulo2PowN(initial, delta);
                var initial1 = initial;
                tasks.Add(Task.Run(() =>
                {
                    var currentBlock = message.Skip(i1 * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                    return _encoder.Encrypt(initial1.Xor(currentBlock), roundKeys);
                }));
            }
            var result =  Task.WhenAll(tasks);
            
            return initialBlock.Concat(result.Result.SelectMany(block => block).ToArray()).ToArray();
        }
        
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys)
        {
            var initial =  _encoder.Decrypt(message.Take(_encoder.BlockSize).ToArray(), roundKeys);
            var delta = initial.Skip(initial.Length - 8).ToArray();

            var tasks = new List<Task<byte[]>>();
            for (var i = 1; i < message.Length / _encoder.BlockSize; i++)
            {
                var i1 = i;
                initial = ByteArrayAdditionByModulo2PowN(initial, delta);
                var initial1 = initial;
                tasks.Add(Task.Run(() =>
                {
                    var currentBlock =message.Skip(i1 * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                    return initial1.Xor(_encoder.Decrypt(currentBlock, roundKeys));
                }));
            }
            var decrypted =  Task.WhenAll(tasks);
            var result = decrypted.Result.SelectMany(block => block).ToArray();
            Array.Resize(ref result, result.Length - result[^1]);
            
            return result;
        }
    }
}