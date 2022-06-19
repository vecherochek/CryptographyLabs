using System.Linq;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class RoundKeyGenerator: IRoundKeyGenerator
    {
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            var roundKeys = new byte[16][];
            var currentC = Permutation(key, Tables.KeyPermutationC);
            var currentD = Permutation(key, Tables.KeyPermutationD);
            for (var i = 0; i < 16; ++i)
            {
                currentC = ShiftLeft(currentC, Tables.KeyShift[i]);
                currentD = ShiftLeft(currentD, Tables.KeyShift[i]);
                
                var currentKey = currentC.Concat(currentD).ToArray();
                roundKeys[i] = Permutation(currentKey, Tables.KeyСompressionPermutation);
            }

            return roundKeys;
        }
    }
}