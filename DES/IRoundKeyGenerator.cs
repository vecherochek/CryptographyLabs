namespace DES
{
    public interface IRoundKeyGenerator
    {
        public byte[][] GenerateRoundKeys(byte[] key);
    }
}