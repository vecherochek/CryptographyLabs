using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class DESFeistelFunction: IEncryptionTransformation
    {
        public byte[] Transform(byte[] block, byte[] roundKey)
        {
            var expandingPermutation = Permutation(block, Tables.ExpandingPermutation);
            var xor = expandingPermutation.Xor(roundKey);
            var SBlock = PermutationSBlock(xor, Tables.SBlocks);
            
            return Permutation(SBlock, Tables.PBlock);
        }
    }
}