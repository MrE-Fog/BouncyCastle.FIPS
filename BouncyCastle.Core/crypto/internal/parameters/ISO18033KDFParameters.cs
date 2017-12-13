using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
	/**
	* parameters for Key derivation functions for ISO-18033
	*/
	internal class Iso18033KdfParameters
		: IDerivationParameters
	{
		byte[]  seed;

		public Iso18033KdfParameters(
			byte[]  seed)
		{
			this.seed = seed;
		}

		public byte[] GetSeed()
		{
			return seed;
		}
	}
}
