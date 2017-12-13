using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public abstract class AuthenticationParameters<TParam, TAlg>
        : Parameters<TAlg>, IAuthenticationParameters<TParam, TAlg>
        where TParam : IParameters<TAlg>
        where TAlg : Algorithm
	{
		private readonly int macSizeInBits;

		internal AuthenticationParameters(TAlg algorithm, int macSizeInBits)
            : base(algorithm)
		{
			this.macSizeInBits = macSizeInBits;
		}

		/// <summary>
		/// Return the size of the MAC these parameters are for.
		/// </summary>
		/// <value>The MAC size in bits.</value>
		public int MacSizeInBits { get { return macSizeInBits; } }

		/// <summary>
		/// Create a new parameter set with the specified MAC size associated with it.
		/// </summary>
		/// <returns>The new parameter set.</returns>
		/// <param name="macSizeInBits">Mac size in bits.</param>
		public TParam WithMacSize(int macSizeInBits)
		{
			return CreateParameter(Algorithm, macSizeInBits);
		}

		internal abstract TParam CreateParameter(TAlg algorithm, int macSizeInBits);
	}
}
