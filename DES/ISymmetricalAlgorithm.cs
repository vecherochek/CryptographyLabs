namespace DES
{
    public interface ISymmetricalAlgorithm
    {
        public byte[] Encrypt(byte[] block);
        public byte[] Decrypt(byte[] block);
        public void GenerateRoundKeys(byte[] key);
    }
}