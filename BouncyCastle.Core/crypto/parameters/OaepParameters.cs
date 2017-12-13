using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Base class for OAEP parameter objects.
    /// </summary>
    /// <typeparam name="TParam">The actual parameter type.</typeparam>
    /// <typeparam name="TAlg">The algorithm type for the parameters.</typeparam>
    /// <typeparam name="DAlg">The digest algorithm type for the parameters.</typeparam>
	public abstract class OaepParameters<TParam, TAlg, DAlg>: Parameters<TAlg>, IOaepParameters<TParam, TAlg, DAlg> where TParam: IParameters<TAlg> where TAlg: Algorithm where DAlg: DigestAlgorithm
	{
		private readonly DAlg digestAlgorithm;
		private readonly DAlg mgfAlgorithm;
		private readonly byte[] encodingParams;

		internal OaepParameters(TAlg algorithm, DAlg digestAlgorithm, DAlg mgfAlgorithm, byte[] encodingParams): base(algorithm)
		{
			this.digestAlgorithm = digestAlgorithm;
			this.mgfAlgorithm = mgfAlgorithm;
			this.encodingParams = encodingParams;
		}

        /// <summary>
        /// Return the digest algorithm associated with these parameters.
        /// </summary>
		public DAlg DigestAlgorithm
		{
			get {
				return digestAlgorithm;
			}
		}

        /// <summary>
        /// Return the digest algorithm used in the mask generation function associated with these parameters.
        /// </summary>
        public DAlg MgfDigestAlgorithm
        {
            get
            {
                return mgfAlgorithm;
            }
        }

        /// <summary>
        /// Return the encoding parameters to be used in the padding created from these parameters.
        /// </summary>
        /// <returns>A copy of the encoding parameters.</returns>
        public byte[] GetEncodingParams()
        {
            return Arrays.Clone(encodingParams);
        }

        /// <summary>
        /// Return a new parameters object which uses the passed in digest algorithm in the OAEP padding.
        /// </summary>
        /// <param name="digestAlgorithm">A digest algorithm.</param>
        /// <returns>A new parameters object.</returns>
        public TParam WithDigest(DAlg digestAlgorithm)
		{
			return CreateParameter(Algorithm, digestAlgorithm, digestAlgorithm, encodingParams);
		}

        /// <summary>
        /// Return a new parameters object which uses the passed in digest algorithm for its mask generation function.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to be used in the MGF.</param>
        /// <returns>A new parameters object.</returns>
		public TParam WithMgfDigest (DAlg digestAlgorithm)
		{
			return CreateParameter(Algorithm, digestAlgorithm, mgfAlgorithm, encodingParams);
		}

        /// <summary>
        /// Return a new parameters object which includes the passed in encoding parameters.
        /// </summary>
        /// <param name="encodingParams">The encoding parameters to be included.</param>
        /// <returns>A new parameters object.</returns>
		public TParam WithEncodingParams (byte[] encodingParams)
		{
			return CreateParameter(Algorithm, digestAlgorithm, mgfAlgorithm, Arrays.Clone(encodingParams));
		}

		abstract internal TParam CreateParameter(TAlg algorithm, DAlg digestAlgorithm, DAlg mgfAlgorithm, byte[] encodingParams);
	}
}

