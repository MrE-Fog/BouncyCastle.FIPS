using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs
{
    internal class SphincsPrivateKeyParameters : AsymmetricKeyParameter
    {
        private readonly byte[] keyData;

        public SphincsPrivateKeyParameters(byte[] keyData) : base(true)
        {
            this.keyData = Arrays.Clone(keyData);
        }

        public byte[] GetKeyData()
        {
            return Arrays.Clone(keyData);
        }
    }
}
