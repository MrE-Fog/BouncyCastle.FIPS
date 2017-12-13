using System;

namespace Org.BouncyCastle.Crypto.Internal.Modes.Gcm
{
	internal interface IGcmExponentiator
	{
		void Init(byte[] x);
		void ExponentiateX(long pow, byte[] output);
	}
}
