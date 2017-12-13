using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Base class for authentications parameters with IVs associated with them (e.g. for CCM, etc)
    /// </summary>
    /// <typeparam name="TParam">Extending type.</typeparam>
    /// <typeparam name="TAlg">Algorithm type associated with extending class.</typeparam>
	public abstract class AuthenticationParametersWithIV<TParam, TAlg>
        : AuthenticationParameters<TParam, TAlg>, IAuthenticationParametersWithIV<TParam, TAlg>
        where TParam : IParameters<TAlg>
        where TAlg : Algorithm
	{
		private readonly byte[] iv;
		private readonly int defaultIvSize;

		internal AuthenticationParametersWithIV(TAlg algorithm, int macSize, int defaultIvSize, byte[] iv)
            : base(algorithm, macSize)
		{
			//((Mode)algorithm.basicVariation()).checkIv(iv, 16);
			this.iv = iv;
		}

        /// <summary>
        /// Return a copy of the IV, null if there isn't one.
        /// </summary>
        /// <returns>A copy of the IV.</returns>
		public byte[] GetIV()
		{
			return Arrays.Clone(iv);
		}

		internal byte[] CreateDefaultIvIfNecessary(int size, SecureRandom random)
		{
			if (Algorithm.Mode != AlgorithmMode.NONE) {
				AlgorithmModeDetails details = AlgorithmModeDetails.GetDetails (Algorithm.Mode);

				if (details != null && details.ExpectsIV) {
					byte[] iv = new byte[size];

					random.NextBytes (iv);

					return iv;
				}
			}
			return null;
		}

		/// <summary>
		/// Create a new parameter set with a different IV.
		/// </summary>
		/// <returns>A copy of the current parameter set with the new IV.</returns>
		/// <param name="iv">The IV to use.</param>
		public TParam WithIV(byte[] iv)
		{
			return CreateParameter(Algorithm, MacSizeInBits, iv);
		}

		/// <summary>
		/// Create a new parameter set with a different IV based on the output
		/// of the passed in random.
		/// </summary>
		/// <returns>A copy of the current parameter set with the new IV.</returns>
		/// <param name="random">A SecureRandom for deriving the IV.</param>
		public virtual TParam WithIV(SecureRandom random)
		{
			return CreateParameter(Algorithm, MacSizeInBits, CreateDefaultIvIfNecessary(defaultIvSize, random));
		}

        /// <summary>
        /// Create a new parameter set with a different IV based on the output
        /// of the passed in random.
        /// </summary>
        /// <returns>A copy of the current parameter set with the new IV.</returns>
        /// <param name="random">A SecureRandom for deriving the IV.</param>
        /// <param name="ivLen">Length of the IV to generate.</param>
        public virtual TParam WithIV(SecureRandom random, int ivLen)
		{
			return CreateParameter(Algorithm, MacSizeInBits, CreateDefaultIvIfNecessary(defaultIvSize, random));
		}

		internal override TParam CreateParameter(TAlg algorithm, int macSizeInBits)
		{
			return CreateParameter(Algorithm, macSizeInBits, iv);
		}

		internal abstract TParam CreateParameter(TAlg algorithm, int macSizeInBits, byte[] iv);
	}
}

