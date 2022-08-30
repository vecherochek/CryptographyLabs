﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SymmetricalAlgorithm;
using static Cryptography.Extensions.ByteArrayExtensions;

namespace CipherContext.EncryptionModes
{
    internal class CTR : IEncryptionMode
    {
        private ISymmetricalAlgorithm _encoder;

        public CTR(ISymmetricalAlgorithm encryptor)
        {
            _encoder = encryptor;
        }

        public async Task<byte[]> EncryptBlockAsync(byte[] message, byte[][] roundKeys, object[] initializationVector)
        {
            var counter = new byte[_encoder.BlockSize];

            Array.Copy((byte[]) initializationVector[0], counter, _encoder.BlockSize);
            var tasks = new List<Task<byte[]>>();
            for (var i = 0; i < message.Length / _encoder.BlockSize; i++)
            {
                var i1 = i;
                tasks.Add(Task.Run(() =>
                {
                    var currentBlock = message.Skip(i1 * _encoder.BlockSize).Take(_encoder.BlockSize).ToArray();
                    return _encoder
                        .Encrypt(ByteArrayAdditionByModulo2PowN(counter, BitConverter.GetBytes(i1)), roundKeys)
                        .Xor(currentBlock);
                }, default));
            }

            var result = await Task.WhenAll(tasks).ConfigureAwait(false);

            return result.SelectMany(block => block).ToArray();
        }

        public async Task<byte[]> DecryptBlockAsync(byte[] message, byte[][] roundKeys, object[] initializationVector)
        {
            var result = await EncryptBlockAsync(message, roundKeys, initializationVector);
            Array.Resize(ref result, message.Length - result[^1]);

            return result;
        }
    }
}