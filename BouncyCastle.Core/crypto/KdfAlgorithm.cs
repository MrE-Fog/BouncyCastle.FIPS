namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Specific Algorithm for representing pairing of a base algorithm and a PRF in a KDF.
    /// </summary>
    public class KdfAlgorithm: Algorithm
    {
        private readonly Algorithm kdfAlgorithm;
        private readonly PrfAlgorithm prfAlgorithm;

        internal KdfAlgorithm(Algorithm kdfAlgorithm, PrfAlgorithm prfAlgorithm): base(kdfAlgorithm.Name + "/" + prfAlgorithm.BaseAlgorithm.Name)
        {
            this.kdfAlgorithm = kdfAlgorithm;
            this.prfAlgorithm = prfAlgorithm;
        }

        /// <summary>
        /// Return the algorithm representing the KDF.
        /// </summary>
        public Algorithm Kdf
        {
            get
            {
                return kdfAlgorithm;
            }
        }

        /// <summary>
        /// Return an algorithm representing the PRF used by the KDF.
        /// </summary>
        public PrfAlgorithm Prf
        {
            get
            {
                return prfAlgorithm;
            }
        }
    }
}
