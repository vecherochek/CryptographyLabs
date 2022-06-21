using System;
using System.Linq;

namespace DES
{
    public class ECB
    {
        private ISymmetricalAlgorithm _encoder;
        
        public ECB(ISymmetricalAlgorithm encryptor)
        {
            _encoder = encryptor;
        }
        
        public byte[] EncryptBlock(byte[] message, byte[][] roundKeys)
        {
            var result = new byte[message.Length];
            for (var i = 0; i < result.Length / _encoder.BlockSize; i++)
            {
                var currentBlock = message.Skip(i * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                currentBlock = _encoder.Encrypt(currentBlock, roundKeys);
                Array.Copy(currentBlock, 0, result, i * _encoder.BlockSize, _encoder.BlockSize);
            }

            return result;
        }
        
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys)
        {
            var result = new byte[message.Length];
            for (var i = 0; i < result.Length / _encoder.BlockSize; i++)
            {
                var currentBlock = message.Skip(i * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                currentBlock = _encoder.Decrypt(currentBlock, roundKeys);
                Array.Copy(currentBlock, 0, result, i * _encoder.BlockSize, _encoder.BlockSize);
            }
            Array.Resize(ref result, message.Length - result[^1]);
            
            return result;
        }
    }
}