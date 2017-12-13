using System;

namespace Org.BouncyCastle.Crypto.Internal.Modes.Gcm
{
	internal interface IGcmMultiplier
	{
		void Init(byte[] H);
		void MultiplyH(byte[] x);
	}
}
