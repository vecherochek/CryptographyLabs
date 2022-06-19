using System;

namespace Cryptography.Extensions
{
    public static class ByteArrayExtensions
    {
        public static byte[] Permutation(byte[] block, byte[] permutationTable)
        {
            var number = BitConverter.ToUInt64(block, 0);
            ulong changed = 0;
            for (var i = 0; i < permutationTable.Length; ++i)
            {
                var findBit = (number >> (permutationTable[i] - 1)) & 1;
                changed |= findBit << i;
            }
            
            return BitConverter.GetBytes(changed);
        }
        
        public static byte[] PermutationSBlock(byte[] block, byte[,,] permutationTable)
        {
            var number = BitConverter.ToUInt64(block, 0);
            ulong result = 0;
            for (var i = 0; i < 8; i++)
            {
                var B = (number >> (i * 6)) & ((uint)1 << 6) - 1;
                var a = ((B >> 5) << 1) | (B & 1);
                var b = (B >> 1) & 0b1111;

                B = permutationTable[i, a, b];
                result|= B << i * 4;
            }
            
            return BitConverter.GetBytes(result);
        }
        
        public static byte[] Xor(this byte[] left, byte[] right)
        {
            if (left is null)
            {
                throw new ArgumentNullException(nameof(left));
            }
            
            if (right is null)
            {
                throw new ArgumentNullException(nameof(right));
            }
            
            if (left.Length != right.Length)
            {
                throw new ArgumentException("Arrays lengths must be equal.");
            }

            for (var i = 0; i < left.Length; i++)
            {
                left[i] ^= right[i];
            }

            return left;
        }
        
        public static byte[] ShiftLeft(byte[] number, byte shift)
        {
            var value = BitConverter.ToUInt32(number);
            
            return  BitConverter.GetBytes(((value << shift) | (value >> (28 - shift)))& ((1 << 28) - 1));
        }
    }
}