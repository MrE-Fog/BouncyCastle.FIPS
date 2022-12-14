using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Base class for key agreement parameters.
    /// </summary>
    /// <typeparam name="TAlg">Acceptable algorithm type.</typeparam>
    /// <typeparam name="TDigest">Acceptable digest algorithm type.</typeparam>
    /// <typeparam name="TPrf">Acceptable PRF type.</typeparam>
    /// <typeparam name="TKdf">Acceptable KDF type.</typeparam>
	public class AgreementParameters<TAlg, TDigest, TPrf, TKdf>: Parameters<TAlg> where TAlg: Algorithm where TDigest: DigestAlgorithm where TPrf: PrfAlgorithm where TKdf :KdfAlgorithm
	{
		private readonly TPrf prfAlgorithm;
		private readonly byte[] salt;
		private readonly TKdf kdf;
		private readonly int outputSize;
        private readonly IKMGenerator kmGenerator;
			
		/// <summary>
		/// Constructor which specifies returning a MAC/HMAC of the raw secret on agreement calculation using one of the
		/// standard PRFs as described in SP800-56C.
		/// </summary>
		/// <param name="agreementAlgorithm">The agreement algorithm these parameters are for.</param>
		/// <param name="prfAlgorithm">The MAC/HMAC algorithm to use.</param>
		/// <param name="salt">The byte string to key the MAC/HMAC with.</param>
		internal AgreementParameters(TAlg agreementAlgorithm, TPrf prfAlgorithm, byte[] salt): base(agreementAlgorithm)
		{
			if (prfAlgorithm == null)
			{
				throw new ArgumentException("prfAlgorithm cannot be null");
			}
			if (salt == null)
			{
				throw new ArgumentException("salt cannot be null");
			}
				
			this.prfAlgorithm = prfAlgorithm;
			this.salt = Arrays.Clone(salt);
			this.kdf = null;
			this.outputSize = 0;
		}

        /// <summary>
        /// Constructor with a KDF to process the Z value with. The outputSize parameter determines how many bytes
        /// will be generated.
        /// </summary>
        /// <param name="agreementAlgorithm">The agreement algorithm these parameters are for.</param>
        /// <param name="kdf">KDF algorithm type to use for parameter creation.</param>
        /// <param name="iv">The iv parameter for KDF initialization.</param>
        /// <param name="outputSize">The size of the output to be generated from the KDF.</param>
        internal AgreementParameters(TAlg agreementAlgorithm, TKdf kdf, byte[] iv, int outputSize): base(agreementAlgorithm)
		{
			if (kdf == null)
			{
				throw new ArgumentException("kdf algorithm cannot be null");
			}
			if (outputSize <= 0)
			{
				throw new ArgumentException("outputSize must be greater than zero");
			}

			this.prfAlgorithm = null;
			this.salt = Arrays.Clone(iv);
            this.kdf = kdf;
			this.outputSize = outputSize;
		}

        internal AgreementParameters(TAlg agreementAlgorithm, IKMGenerator kmGenerator) : base(agreementAlgorithm)
        {
            this.kmGenerator = kmGenerator;
        }

        /// <summary>
        /// Return the KDF algorithm type.
        /// </summary>
        /// <value>The KDF algorithm, null if not present.</value>
        public TKdf Kdf
        {
            get
            {
                return kdf;
            }
        }

        /// <summary>
        /// Return the size of the output required from the KDF.
        /// </summary>
        /// <value>The number of bytes to be generated by a KDF using these parameters.</value>
        public int OutputSize
        {
            get
            {
                return outputSize;
            }
        }

		/// <summary>
		/// Return the salt/iv associated with these parameters.
		/// </summary>
		/// <returns>The salt, null if not present.</returns>
		public byte[] GetSalt()
		{
			return Arrays.Clone(salt);
		}

        public IKMGenerator KeyMaterialGenerator
        {
            get
            {
                return kmGenerator;
            }
        }
	}
}

