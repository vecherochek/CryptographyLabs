using System;
using System.Linq;
using Cryptography.Extensions;

namespace DES
{
    public class CBC
    {
        private ISymmetricalAlgorithm _encoder;
        
        public CBC(ISymmetricalAlgorithm encryptor)
        {
            _encoder = encryptor;
        }
        
        public byte[] EncryptBlock(byte[] message, byte[][] roundKeys, object[] initializationVector)
        {
            var result = new byte[message.Length];
            var prevBlock = new byte[8];
            
            Array.Copy((byte[])initializationVector[0], prevBlock, prevBlock.Length);
            for (var i = 0; i < result.Length / 8; i++)
            {
                var currentBlock = new byte[8];
                
                Array.Copy(message, i * 8, currentBlock, 0, 8);
                currentBlock = prevBlock.Xor(currentBlock);
                prevBlock = _encoder.Encrypt(currentBlock, roundKeys);
                Array.Copy(prevBlock, 0, result, i * 8, 8);
            }

            return result;
        }
        
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys, object[] initializationVector)
        {
            var result = new byte[message.Length];
            var prevBlock = new byte[8];
            
            Array.Copy((byte[])initializationVector[0], prevBlock, prevBlock.Length);
            for (var i = 0; i < result.Length / 8; i++)
            {
                var currentBlock = new byte[8];
                var tmp = new byte[8];
                
                Array.Copy(message, i * 8, currentBlock, 0, 8);
                Array.Copy(currentBlock, tmp , tmp.Length);
                currentBlock = _encoder.Decrypt(currentBlock, roundKeys);
                currentBlock = prevBlock.Xor(currentBlock);
                Array.Copy(tmp, prevBlock, prevBlock.Length);
                Array.Copy(currentBlock, 0, result, i * 8, 8);
            }
            Array.Resize(ref result, message.Length - result[^1]);
            
            return result;
        }
    }
}