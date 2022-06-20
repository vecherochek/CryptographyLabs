using System.Collections;
using System.Linq;
using System.Numerics;
using static Cryptography.Extensions.BitArrayExtensions;
using static Cryptography.Extensions.ByteArrayExtensions;


namespace DES
{
    public class DESRoundKeyGenerator: IRoundKeyGenerator
    {
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            var roundKeys = new byte[16][];
            var keybits = new BitArray(key);
            var currentC = BitsPermutation(keybits, Tables.KeyPermutationC);
            var currentD = BitsPermutation(keybits, Tables.KeyPermutationD);
            
            for (var i = 0; i < 16; ++i)
            {
                currentC = currentC.LeftShift(Tables.KeyShift[i]);
                currentD = currentD.LeftShift(Tables.KeyShift[i]);
                var currentKey = currentC.BitsConcat(currentD);
                roundKeys[i] = BitArrayToByteArray(BitsPermutation(currentKey, Tables.KeyСompressionPermutation));
            }
            //TODO: дописать генерацию ключей, а то чота не робит)))))))
            return roundKeys;
        }
    }
}