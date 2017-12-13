using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Fips
{
	public class FipsDigestAlgorithm: DigestAlgorithm
	{
		internal FipsDigestAlgorithm (string name): base(name)
		{
		}

		internal FipsDigestAlgorithm (string name, AlgorithmMode mode) : base(name, mode)
		{
		}
	}
}

