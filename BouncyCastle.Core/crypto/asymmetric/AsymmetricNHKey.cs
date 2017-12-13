using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Asymmetric
{ 
    public abstract class AsymmetricNHKey: IAsymmetricKey
    {
        private readonly Algorithm mAlg;
        private readonly bool approvedModeOnly;

        internal AsymmetricNHKey(Algorithm alg)
        {
            this.mAlg = alg;
            this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
        }

        public Algorithm Algorithm
        {
            get
            {
                return mAlg;
            }
        }

        internal virtual void CheckApprovedOnlyModeStatus()
        {
            if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
                throw new CryptoUnapprovedOperationError("No access to key in current thread.");
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();
    }
}
