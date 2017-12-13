using System;

namespace Org.BouncyCastle.Crypto.Fips
{
	public class FipsAlgorithm : Algorithm
	{
		internal FipsAlgorithm (string name): base(name, AlgorithmMode.NONE)
		{
		}

		internal FipsAlgorithm (string name, AlgorithmMode mode) : base(name, mode)
		{
		}

		internal FipsAlgorithm (FipsAlgorithm algorithm, AlgorithmMode mode) : base(algorithm.Name, mode)
		{
		}
	}
}

