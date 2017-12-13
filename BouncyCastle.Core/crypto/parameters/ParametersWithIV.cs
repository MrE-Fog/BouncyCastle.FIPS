using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public abstract class ParametersWithIV<TParam, TAlg>: Parameters<TAlg>, IParametersWithIV<TParam, TAlg> where TParam: IParameters<TAlg> where TAlg: Algorithm
	{
		private readonly byte[] iv;
		private readonly int defaultIvSize;

		internal ParametersWithIV(TAlg algorithm, int defaultIvSize, byte[] iv):base(algorithm)
		{
			Utils.CheckIv(algorithm.Mode, iv, defaultIvSize);

			this.defaultIvSize = defaultIvSize;
			this.iv = iv;
		}
			
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
			return CreateParameter(Algorithm, Arrays.Clone(iv));
		}

		/// <summary>
		/// Create a new parameter set with a different IV based on the output
		/// of the passed in random.
		/// </summary>
		/// <returns>A copy of the current parameter set with the new IV.</returns>
		/// <param name="random">A SecureRandom for deriving the IV.</param>
		public TParam WithIV(SecureRandom random)
		{
			return CreateParameter(Algorithm, CreateDefaultIvIfNecessary(defaultIvSize, random));
		}

		abstract internal TParam CreateParameter(TAlg algorithm, byte[] iv);
	}
}

