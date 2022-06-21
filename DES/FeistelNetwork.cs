using System.Linq;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class FeistelNetwork: ISymmetricalAlgorithm
    {
        private readonly IRoundKeyGenerator _roundKeysGenerator;
        private readonly IEncryptionTransformation _feistelFunction;
        
        public FeistelNetwork(IRoundKeyGenerator roundKeysGenerator, IEncryptionTransformation feistelFunction)
        {
            _roundKeysGenerator = roundKeysGenerator;
            _feistelFunction = feistelFunction;
        }

        public byte[] Encrypt(byte[] block, byte[][] roundKeys)
        {
            var left = block.Take(block.Length / 2).ToArray();
            var right = block.Skip(block.Length / 2).ToArray();
            for (var i = 0; i < 16; i++)
            {
                var tmp = right;
                right = left.Xor(_feistelFunction.Transform(right, roundKeys[i]));
                left = tmp;
            }

            return left.Concat(right).ToArray();
        }
        
        public byte[] Decrypt(byte[] block, byte[][] roundKeys)
        {
            var left = block.Take(block.Length / 2).ToArray();
            var right = block.Skip(block.Length / 2).ToArray();
            for (var i = 15; i >= 0; i--)
            {
                var tmp = left;
                left = right.Xor(_feistelFunction.Transform(left, roundKeys[i]));
                right = tmp;
            }

            return left.Concat(right).ToArray();
        }

        public byte[][] GenerateRoundKeys(byte[] key)
        {
            return _roundKeysGenerator.GenerateRoundKeys(key);
        }
    }
}