using Org.BouncyCastle.Ans1.BC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for SPHINCS-256 keys.
    /// </summary>
    public abstract class AsymmetricSphincsKey
    {
        private readonly bool approvedModeOnly;
        private readonly Algorithm algorithm;
        private readonly DigestAlgorithm treeAlgorithm;

        protected readonly Sphincs256KeyParams parameters;

        internal AsymmetricSphincsKey(Algorithm algorithm, Sphincs256KeyParams parameters)
        {
            this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
            this.algorithm = algorithm;
            this.parameters = parameters;
            this.treeAlgorithm = parameters.TreeDigest.Algorithm.Equals(NistObjectIdentifiers.IdSha3_256) ? FipsShs.Sha3_256 : FipsShs.Sha512_256;
        }

        internal AsymmetricSphincsKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier): this(algorithm, Sphincs256KeyParams.GetInstance(algorithmIdentifier.Parameters)) 
		{
        }

        internal AsymmetricSphincsKey(Algorithm algorithm, DigestAlgorithm treeAlgorithm) : this(algorithm, getParameters(treeAlgorithm))
        {
        }

        private static Sphincs256KeyParams getParameters(DigestAlgorithm algorithm)
        {
            if (algorithm == FipsShs.Sha3_256.Algorithm)
            {
                return new Sphincs256KeyParams(new AlgorithmIdentifier(NistObjectIdentifiers.IdSha3_256));
            }
            else
            {
                return new Sphincs256KeyParams(new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512_256));
            }
        }

        /// <summary>
        /// Return the algorithm this SPHINCS key is for.
        /// </summary>
        /// <value>The key's algorithm.</value>
        public Algorithm Algorithm
        {
            get
            {
                if (this is AsymmetricSphincsPrivateKey)
                {
                    checkApprovedOnlyModeStatus();
                }

                return algorithm;
            }
        }

        /// <summary>
        /// Return the digest algorithm used to construct the tree for the public key.
        /// </summary>
        /// <value>The key digest algorithm for tree construction.</value>
        public DigestAlgorithm TreeDigestAlgorithm
        {
            get
            {
                return treeAlgorithm;
            }
        }

        /// <summary>
        /// Return the key data (a byte representation of the digest tree used in signature processing).
        /// </summary>
        /// <returns>The key data.</returns>
        public abstract byte[] GetKeyData();

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();

        internal void checkApprovedOnlyModeStatus()
        {
            if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("No access to key in current thread.");
            }
        }
    }
}
