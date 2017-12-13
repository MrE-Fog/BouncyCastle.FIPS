using System;

using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Crypto.General
{
	public class GeneralAlgorithm : Algorithm
	{
		internal GeneralAlgorithm (string name): base(name, AlgorithmMode.NONE)
		{
		}

		internal GeneralAlgorithm (Algorithm algorithm, AlgorithmMode mode) : base(algorithm.Name, mode)
		{
		}
    }
}

