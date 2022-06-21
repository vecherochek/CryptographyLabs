using System;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public enum EncryptionMode
    {
        ECB,
        CBC,
        CFB,
        OFB,
        CTR,
        RD,
        RDH
    };
    
    public class CipherContext
    {
        private readonly byte[] _key;    
        private readonly EncryptionMode _encryptionMode;
        public ISymmetricalAlgorithm Encoder { get; set; }
        public CipherContext(byte[] key, EncryptionMode encryptionMode, params object[] values)
        {
            _key = key;
            _encryptionMode = encryptionMode;
        }

        public byte[] Encrypt(byte[] message, byte[][] roundKeys)
        {
            var original = PaddingPKCs7(message, 8);
            
            switch (_encryptionMode)
            {
                case EncryptionMode.ECB: 
                    return new ECB(Encoder).EncryptBlock(original, roundKeys);
                
                default: 
                    throw new ArgumentOutOfRangeException(nameof(_encryptionMode), _encryptionMode, null);
            }
        }
        public byte[] Decrypt(byte[] message, byte[][] roundKeys)
        {
            switch (_encryptionMode)
            {
                case EncryptionMode.ECB: 
                    return new ECB(Encoder).DecryptBlock(message, roundKeys);
                
                default: 
                    throw new ArgumentOutOfRangeException(nameof(_encryptionMode), _encryptionMode, null);
            }
        }
        public byte[][] GenerateRoundKeys()
        {
            return Encoder.GenerateRoundKeys(_key);
        }
    }
}