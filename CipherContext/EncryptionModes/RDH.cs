using System;
using System.Linq;
using SymmetricalAlgorithm;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace CipherContext.EncryptionModes
{
    internal class RDH
    {
        private ISymmetricalAlgorithm _encoder;
        
        public RDH(ISymmetricalAlgorithm encryptor)
        {
            _encoder = encryptor;
        }
        
        public byte[] EncryptBlock(byte[] message, byte[][] roundKeys, object[] values)
        {
            var result = new byte[message.Length + 2 * _encoder.BlockSize];
            var initial = new byte[_encoder.BlockSize];
            var hash = new byte[_encoder.BlockSize];
            
            Array.Copy((byte[])values[0], initial, _encoder.BlockSize);
            Array.Copy(
                PaddingPKCs7(BitConverter.GetBytes(values[1].GetHashCode()), _encoder.BlockSize), 
                hash,
                _encoder.BlockSize);

            Array.Copy(_encoder.Encrypt(initial, roundKeys), 0, result, 0, _encoder.BlockSize);
            Array.Copy(_encoder.Encrypt(initial.Xor(hash), roundKeys), 0, result, _encoder.BlockSize, _encoder.BlockSize);
            
            var delta = initial.Skip(initial.Length - 8).ToArray();
            delta[0] |= 0x01;
            for (var i = 0; i < message.Length / _encoder.BlockSize; i++)
            {
                var currentBlock = message.Skip(i * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                currentBlock = initial.Xor(currentBlock);
                currentBlock = _encoder.Encrypt(currentBlock, roundKeys);
                
                Array.Copy(currentBlock, 0, result, (i + 2) * _encoder.BlockSize, _encoder.BlockSize);
                initial = ByteArrayAdditionByModulo2PowN(initial, delta);
            }

            return result;
        }
        
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys)
        {
            var result = new byte[message.Length - 2 * _encoder.BlockSize];
            var initial =  _encoder.Decrypt(message.Take(_encoder.BlockSize).ToArray(), roundKeys);
            //var hash = _encoder.Decrypt(message.Skip(_encoder.BlockSize).Take(_encoder.BlockSize).ToArray(), roundKeys).Xor(initial);
            
            var delta = initial.Skip(_encoder.BlockSize - 8).ToArray();
            for (var i = 2; i < message.Length / _encoder.BlockSize; i++)
            {
                var currentBlock = message.Skip(i * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                currentBlock = _encoder.Decrypt(currentBlock, roundKeys);
                currentBlock = initial.Xor(currentBlock);
                
                Array.Copy(currentBlock, 0, result, (i - 2) * _encoder.BlockSize, _encoder.BlockSize);
                initial =  ByteArrayAdditionByModulo2PowN(initial, delta);
            }
            Array.Resize(ref result, result.Length - result[^1]);
            
            return result;
        }
    }
}