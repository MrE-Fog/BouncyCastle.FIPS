using System;

namespace Org.BouncyCastle.Crypto
{
	internal interface IDrbgProvider
	{
		IDrbg Get(IEntropySource entropySource);
	}
}

