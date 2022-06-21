﻿using System;
using System.Collections;

namespace Cryptography.Extensions
{
    public static class ByteArrayExtensions
    {
        public static byte[] Permutation(byte[] block, byte[] permutationTable)
        {
            var bitsblock = new BitArray(block);

            var changed = new BitArray(permutationTable.Length);
            for (var i = 0; i < permutationTable.Length; i++)
            {
                changed[i] = bitsblock[permutationTable[i] - 1];
            }
            
            return BitArrayToByteArray(changed);
        }
        public static byte[] BitArrayToByteArray(BitArray bits)
        {
            byte[] bytes = new byte[(bits.Length - 1) / 8 + 1];
            bits.CopyTo(bytes, 0);
            return bytes;
        }
        public static byte[] PermutationSBlock(byte[] block, byte[,,] permutationTable)
        {
            var number = BitConverter.ToUInt32(block, 0);
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
        
        public static byte[] PaddingPKCs7(byte[] block, int blockSize)
        {
            var addition = (byte) (blockSize - block.Length % blockSize);
            var paddedBlock = new byte[block.Length + addition];
            Array.Copy(block, paddedBlock, block.Length);
            Array.Fill(paddedBlock, addition, block.Length, addition); 
            
            return paddedBlock;
        }
    }
}