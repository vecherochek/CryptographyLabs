using System;
using System.Threading.Tasks;
using CipherContext.EncryptionModes;
using SymmetricalAlgorithm;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace CipherContext
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

        public async Task<byte[]> Encrypt(byte[] message, byte[][] roundKeys)
        {
            var original = PaddingPKCs7(message, Encoder.BlockSize);

            return _encryptionMode switch
            {
                EncryptionMode.ECB => await Task.Run(() => new ECB(Encoder).EncryptBlock(original, roundKeys)),
                EncryptionMode.CBC => await Task.Run(() => new CBC(Encoder).EncryptBlock(original, roundKeys, _values)),
                EncryptionMode.CFB => await Task.Run(() => new CFB(Encoder).EncryptBlock(original, roundKeys, _values)),
                EncryptionMode.OFB => await Task.Run(() => new OFB(Encoder).EncryptBlock(original, roundKeys, _values)),
                EncryptionMode.CTR => await Task.Run(() => new CTR(Encoder).EncryptBlock(original, roundKeys, _values)),
                EncryptionMode.RD => await Task.Run(() => new RD(Encoder).EncryptBlock(original, roundKeys, _values)),
                EncryptionMode.RDH => await Task.Run(() => new RDH(Encoder).EncryptBlock(original, roundKeys, _values)),
                _ => throw new ArgumentOutOfRangeException(nameof(_encryptionMode), _encryptionMode, "kek")
            };
        }
        public async Task<byte[]> Decrypt(byte[] message, byte[][] roundKeys)
        {
            return _encryptionMode switch 
            {
                EncryptionMode.ECB => await Task.Run(() => new ECB(Encoder).DecryptBlock(message, roundKeys)),
                EncryptionMode.CBC => await Task.Run(() => new CBC(Encoder).DecryptBlock(message, roundKeys, _values)),
                EncryptionMode.CFB => await Task.Run(() => new CFB(Encoder).DecryptBlock(message, roundKeys, _values)),
                EncryptionMode.OFB => await Task.Run(() => new OFB(Encoder).DecryptBlock(message, roundKeys, _values)),
                EncryptionMode.CTR => await Task.Run(() => new CTR(Encoder).DecryptBlock(message, roundKeys, _values)),
                EncryptionMode.RD => await Task.Run(() => new RD(Encoder).DecryptBlock(message, roundKeys)),
                EncryptionMode.RDH => await Task.Run(() => new RDH(Encoder).DecryptBlock(message, roundKeys)),
                _ => throw new ArgumentOutOfRangeException(nameof(_encryptionMode), _encryptionMode, "kek")
            };
        }
        public byte[][] GenerateRoundKeys()
        {
            return Encoder.GenerateRoundKeys(_key);
        }
    }
    
}