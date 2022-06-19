using System.Linq;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class FeistelNetwork: ISymmetricalAlgorithm
    {
        private readonly IRoundKeyGenerator _roundKeysGenerator;
        private readonly IEncryptionTransformation _feistelFunction;
        private byte[][] _roundKeys;
        
        public FeistelNetwork(IRoundKeyGenerator roundKeysGenerator, IEncryptionTransformation feistelFunction)
        {
            _roundKeysGenerator = roundKeysGenerator;
            _feistelFunction = feistelFunction;
        }

        public byte[] Encrypt(byte[] block)
        {
            var left = block.Take(block.Length / 2).ToArray();
            var right = block.Skip(block.Length / 2).ToArray();
            for (var i = 0; i < 16; i++)
            {
                var tmp = right;
                right = left.Xor(_feistelFunction.Transform(right, _roundKeys[i]));
                left = tmp;
            }

            return left.Concat(right).ToArray();
        }

        public byte[] Decrypt(byte[] block)
        {
            var left = block.Take(block.Length / 2).ToArray();
            var right = block.Skip(block.Length / 2).ToArray();
            for (var i = 15; i >= 0; i--)
            {
                var tmp = left;
                left = right.Xor(_feistelFunction.Transform(right, _roundKeys[i]));
                right = tmp;
            }

            return left.Concat(right).ToArray();
        }

        public void GenerateRoundKeys(byte[] key)
        {
            _roundKeys = _roundKeysGenerator.GenerateRoundKeys(key);
        }
    }
}