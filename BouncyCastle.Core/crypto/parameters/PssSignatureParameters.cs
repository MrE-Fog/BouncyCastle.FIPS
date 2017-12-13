
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{	
    /// <summary>
    /// Base class for PSS signature parameters.
    /// </summary>
    /// <typeparam name="TParam">Type extending this one.</typeparam>
    /// <typeparam name="TAlg">The type of algorithm the parameters are for.</typeparam>
    /// <typeparam name="DAlg">The type of digest the parameters are for.</typeparam>
	public abstract class PssSignatureParameters<TParam, TAlg, DAlg>: Parameters<TAlg>, IPssSignatureParameters<TParam, TAlg, DAlg> where TParam: IParameters<TAlg> where TAlg: Algorithm where DAlg: DigestAlgorithm
	{
		private readonly DAlg digestAlgorithm;
		private readonly DAlg mgfAlgorithm;
        private readonly int mSaltLength;
		private readonly byte[] salt;

		internal PssSignatureParameters(TAlg algorithm, DAlg digestAlgorithm, DAlg mgfAlgorithm, int saltLength, byte[] salt): base(algorithm)
		{
			this.digestAlgorithm = digestAlgorithm;
			this.mgfAlgorithm = mgfAlgorithm;
            this.mSaltLength = saltLength;
			this.salt = salt;
		}

        /// <summary>
        /// Return the digest algorithm for processing the message to be signed.
        /// </summary>
		public DAlg DigestAlgorithm
		{
			get {
				return digestAlgorithm;
			}
		}

        /// <summary>
        /// Return the digest algorithm to be used in the mask generation function.
        /// </summary>
        public DAlg MgfDigestAlgorithm
        {
            get
            {
                return mgfAlgorithm;
            }
        }

        /// <summary>
        /// Return the length of the salt specified for these parameters.
        /// </summary>
        public int SaltLength
        {
            get
            {
                if (salt != null)
                {
                    return salt.Length;
                }

                return mSaltLength;
            }
        }

        /// <summary>
        /// Return the fixed salt the parameters are configured with, if present.
        /// </summary>
        /// <returns>The fixed salt if available, null otherwise.</returns>
        public byte[] GetSalt()
        {
            return Arrays.Clone(salt);
        }

        /// <summary>
        /// Set the digest algorithm. Note: this will also set the MGF digest to the same algorithm.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to use.</param>
        /// <returns>A new parameter set with the changed configuration.</returns>
		public TParam WithDigest(DAlg digestAlgorithm)
		{
			return CreateParameter(Algorithm, digestAlgorithm, digestAlgorithm, mSaltLength, salt);
		}

        /// <summary>
        /// Set the MGF digest algorithm explicitly.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorith to use for mask generation.</param>
        /// <returns>A new parameter set with the changed configuration.</returns>
		public TParam WithMgfDigest (DAlg digestAlgorithm)
		{
			return CreateParameter(Algorithm, digestAlgorithm, mgfAlgorithm, mSaltLength, salt);
		}

        /// <summary>
        /// Provide a fixed salt value to use with the signature.
        /// </summary>
        /// <param name="salt">A fixed salt value to use.</param>
        /// <returns>A new parameter set with the changed configuration.</returns>
		public TParam WithSalt (byte[] salt)
		{
			return CreateParameter(Algorithm, digestAlgorithm, mgfAlgorithm, mSaltLength, salt);
		}

        /// <summary>
        /// Specify a length for the salt value in the signature.
        /// </summary>
        /// <param name="saltLength">The length of the salt to use.</param>
        /// <returns>A new parameter set with the changed configuration.</returns>
		public TParam WithSaltLength (int saltLength)
		{
			return CreateParameter(Algorithm, digestAlgorithm, mgfAlgorithm, saltLength, salt);
		}

		abstract internal TParam CreateParameter(TAlg algorithm, DAlg digestAlgorithm, DAlg mgfAlgorithm, int saltLength, byte[] salt);
	}
}

