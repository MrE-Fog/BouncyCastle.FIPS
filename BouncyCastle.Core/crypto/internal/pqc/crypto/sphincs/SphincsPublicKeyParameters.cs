using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class SphincsPublicKeyParameters : AsymmetricKeyParameter
    {
        private readonly byte[] keyData;

        public SphincsPublicKeyParameters(byte[] keyData) : base(false)
        {
            this.keyData = Arrays.Clone(keyData);
        }

        public byte[] GetKeyData()
        {
            return Arrays.Clone(keyData);
        }
    }
}
