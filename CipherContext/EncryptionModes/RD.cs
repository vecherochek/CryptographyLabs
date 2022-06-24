using System;
using System.Linq;
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
            var result = new byte[message.Length + _encoder.BlockSize];
            var initial = new byte[_encoder.BlockSize];
            
            Array.Copy((byte[])initializationVector[0], initial, initial.Length);
            Array.Copy(_encoder.Encrypt(initial, roundKeys), 0, result, 0, _encoder.BlockSize);
            //для дельты всегда берем последние 8 байт вектора инициализации
            var delta = initial.Skip(initial.Length - 8).ToArray();
            //делаем дельту нечетной
            delta[0] |= 0x01;
            for (var i = 0; i < message.Length / _encoder.BlockSize; i++)
            {
                var currentBlock = message.Skip(i * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                currentBlock = initial.Xor(currentBlock);
                currentBlock = _encoder.Encrypt(currentBlock, roundKeys);
                
                Array.Copy(currentBlock, 0, result, (i + 1) * _encoder.BlockSize, _encoder.BlockSize);
                initial = ByteArrayAdditionByModulo2PowN(initial, delta);
            }

            return result;
        }
        
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys)
        {
            var result = new byte[message.Length - _encoder.BlockSize];
            var initial =  _encoder.Decrypt(message.Take(_encoder.BlockSize).ToArray(), roundKeys);
            
            var delta = initial.Skip(initial.Length - 8).ToArray();
            for (var i = 1; i < message.Length / _encoder.BlockSize; i++)
            {
                var currentBlock = message.Skip(i * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                currentBlock = _encoder.Decrypt(currentBlock, roundKeys);
                currentBlock = initial.Xor(currentBlock);
                
                Array.Copy(currentBlock, 0, result, (i - 1) * _encoder.BlockSize, _encoder.BlockSize);
                initial =  ByteArrayAdditionByModulo2PowN(initial, delta);
            }
            Array.Resize(ref result, result.Length - result[^1]);
            
            return result;
        }
    }
}