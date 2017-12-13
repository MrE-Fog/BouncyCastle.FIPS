using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Pair for a value exchange algorithm where the responding party has no private key, such as NewHope.
    /// </summary>
    public class ExchangePair
    {
        private readonly IAsymmetricPublicKey mKey;
        private readonly byte[] mShared;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="key">The responding party's public key.</param>
        /// <param name="shared">The calculated shared value.</param>
        public ExchangePair(IAsymmetricPublicKey key, byte[] shared)
        {
            this.mKey = key;
            this.mShared = Arrays.Clone(shared);
        }

        /// <summary>
        /// Return the responding party's public key.
        /// </summary>
        public IAsymmetricPublicKey PublicKey
        {
            get { return mKey;  }
        }

        /// <summary>
        /// Return the shared value that is associated with the two public keys involved.
        /// </summary>
        /// <returns>The shared value.</returns>
        public byte[] GetSharedValue()
        {
            return Arrays.Clone(mShared);
        }
    }
}
