namespace DES
{
    public interface IEncryptionTransformation
    {
        public byte[] Transform(byte[] block, byte[] roundKey);
    }
}