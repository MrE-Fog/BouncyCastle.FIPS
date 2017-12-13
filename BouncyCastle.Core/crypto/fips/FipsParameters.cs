using System;

namespace Org.BouncyCastle.Crypto.Fips
{
	public class FipsParameters: IParameters<FipsAlgorithm>
	{
		private readonly FipsAlgorithm algorithm;

		// package protect construction
		internal FipsParameters(FipsAlgorithm algorithm)
		{
			this.algorithm = algorithm;
		}
			
		/// <summary>
		/// Return the algorithm these parameters are associated with.
		/// </summary>
		/// <value>The algorithm these parameters are for.</value>
		public FipsAlgorithm Algorithm
		{
			get {
				return algorithm;
			}
		}
	}
}

