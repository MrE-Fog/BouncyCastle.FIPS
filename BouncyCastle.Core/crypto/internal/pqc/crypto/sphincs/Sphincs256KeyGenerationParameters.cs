using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class Sphincs256KeyGenerationParameters : KeyGenerationParameters
    {
        private readonly IDigest treeDigest;

        public Sphincs256KeyGenerationParameters(SecureRandom random, IDigest treeDigest): base(random, SPHINCS256Config.CRYPTO_PUBLICKEYBYTES* 8)
        {
            
            this.treeDigest = treeDigest;
        }

        public IDigest TreeDigest
        {
            get { return treeDigest; }
        }
    }
}
