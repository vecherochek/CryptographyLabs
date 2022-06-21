using System;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class DES: ISymmetricalAlgorithm
    {
        private const int _blockSize = 8;
        private readonly ISymmetricalAlgorithm _feistelNetwork = new FeistelNetwork(new DESRoundKeyGenerator(), new DESFeistelFunction(), _blockSize);

        public int BlockSize => _blockSize;
        public byte[] Encrypt(byte[] block, byte[][] roundKeys)
        {
            if (block.Length != _blockSize)
            {
                throw new ArgumentException($"Block length must be equal to {_blockSize}.");
            }
            
            block = Permutation(block, Tables.InitialPermutation);
            block = _feistelNetwork.Encrypt(block, roundKeys);
            
            return Permutation(block, Tables.FinalPermutation);
        }
        public byte[] Decrypt(byte[] block, byte[][] roundKeys)
        {
            if (block.Length != _blockSize)
            {
                throw new ArgumentException($"Block length must be equal to {_blockSize}.");
            }
            
            block = Permutation(block, Tables.InitialPermutation);
            block = _feistelNetwork.Decrypt(block, roundKeys);
            
            return Permutation(block, Tables.FinalPermutation);
        }
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            return _feistelNetwork.GenerateRoundKeys(key);
        }
    }
}