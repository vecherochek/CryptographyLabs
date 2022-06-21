using System;

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
            for (var i = 0; i < result.Length / 8; i++)
            {
                var currentBlock = new byte[8];
                
                Array.Copy(message, i * 8, currentBlock, 0, 8);
                currentBlock = _encoder.Encrypt(currentBlock, roundKeys);
                Array.Copy(currentBlock, 0, result, i * 8, 8);
            }

            return result;
        }
        
        public byte[] DecryptBlock(byte[] message, byte[][] roundKeys)
        {
            var result = new byte[message.Length];
            for (var i = 0; i < result.Length / 8; i++)
            {
                var currentBlock = new byte[8];

                Array.Copy(message, i * 8, currentBlock, 0, 8);
                currentBlock = _encoder.Decrypt(currentBlock, roundKeys);
                Array.Copy(currentBlock, 0, result, i * 8, 8);
            }
            Array.Resize(ref result, message.Length - result[^1]);
            
            return result;
        }
    }
}