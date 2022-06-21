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
        private readonly object[] _values;
        public ISymmetricalAlgorithm Encoder { get; set; }
        public CipherContext(byte[] key, EncryptionMode encryptionMode, params object[] values)
        {
            _key = key;
            _encryptionMode = encryptionMode;
            _values = values;
        }

        public byte[] Encrypt(byte[] message, byte[][] roundKeys)
        {
            var original = PaddingPKCs7(message, Encoder.BlockSize);
            
            switch (_encryptionMode)
            {
                case EncryptionMode.ECB: 
                    return new ECB(Encoder).EncryptBlock(original, roundKeys);
                case EncryptionMode.CBC:
                    return new CBC(Encoder).EncryptBlock(original, roundKeys, _values);
                case EncryptionMode.CFB:
                    return new CFB(Encoder).EncryptBlock(original, roundKeys, _values);
                case EncryptionMode.OFB:
                    return new OFB(Encoder).EncryptBlock(original, roundKeys, _values);
                case EncryptionMode.CTR:
                    return new CTR(Encoder).EncryptBlock(original, roundKeys, _values);
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
                case EncryptionMode.CBC: 
                    return new CBC(Encoder).DecryptBlock(message, roundKeys, _values);
                case EncryptionMode.CFB: 
                    return new CFB(Encoder).DecryptBlock(message, roundKeys, _values);
                case EncryptionMode.OFB:
                    return new OFB(Encoder).DecryptBlock(message, roundKeys, _values);
                case EncryptionMode.CTR:
                    return new CTR(Encoder).DecryptBlock(message, roundKeys, _values);
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