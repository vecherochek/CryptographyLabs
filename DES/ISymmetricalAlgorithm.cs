namespace DES
{
    public interface ISymmetricalAlgorithm
    {
        public byte[] Encrypt(byte[] block, byte[][] roundKeys);
        public byte[] Decrypt(byte[] block, byte[][] roundKeys);
        public byte[][] GenerateRoundKeys(byte[] key);
    }
}