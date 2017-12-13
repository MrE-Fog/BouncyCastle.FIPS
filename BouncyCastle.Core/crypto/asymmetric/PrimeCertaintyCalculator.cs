using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	internal class PrimeCertaintyCalculator
	{
		private PrimeCertaintyCalculator()
		{

		}
			
		/// <summary>
		/// Return the current wisdom on prime certainty requirements.
		/// </summary>
		/// <returns>A certainty value.</returns>
		/// <param name="keySizeInBits">Size of the key being generated.</param>
		internal static int GetDefaultCertainty(int keySizeInBits)
		{
			// Based on FIPS 186-4 Table C.1
			return keySizeInBits <= 1024 ? 80 : (96 + 16 * ((keySizeInBits - 1) / 1024));
		}
	}
}

