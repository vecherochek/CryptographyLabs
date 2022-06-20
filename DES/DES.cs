using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class DES: ISymmetricalAlgorithm
    {
        private readonly ISymmetricalAlgorithm _feistelNetwork = new FeistelNetwork(new DESRoundKeyGenerator(), new DESFeistelFunction());

        public byte[] Encrypt(byte[] message, byte[][] roundKeys)
        {
            message = Permutation(message, Tables.InitialPermutation);
            message = _feistelNetwork.Encrypt(message, roundKeys);
            
            return Permutation(message, Tables.FinalPermutation);
        }
        public byte[] Decrypt(byte[] message, byte[][] roundKeys)
        {
            message = Permutation(message, Tables.InitialPermutation);
            message = _feistelNetwork.Decrypt(message, roundKeys);
            
            return Permutation(message, Tables.FinalPermutation);
        }
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            return _feistelNetwork.GenerateRoundKeys(key);
        }
    }
}