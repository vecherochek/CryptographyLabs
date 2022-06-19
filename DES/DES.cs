using static Cryptography.Extensions.ByteArrayExtensions;

namespace DES
{
    public class DES: FeistelNetwork
    {
        public DES(IRoundKeyGenerator roundKeysGenerator, IEncryptionTransformation feistelFunction) 
            : base(roundKeysGenerator, feistelFunction){}
        
        private byte[] EncryptMessage(byte[] message)
        {
            message = Permutation(message, Tables.InitialPermutation);
            message = Encrypt(message);
            
            return Permutation(message, Tables.FinalPermutation);
        }
        private byte[] DecryptMessage(byte[] message)
        {
            message = Permutation(message, Tables.InitialPermutation);
            message = Decrypt(message);
            
            return Permutation(message, Tables.FinalPermutation);
        }
        
    }
}