using System;

namespace Org.BouncyCastle.Crypto
{
	public interface ISymmetricWrapParameters<out TParam, out TAlg>
        : IParametersWithIV<TParam, TAlg>
        where TParam : IParameters<TAlg>
        where TAlg : Algorithm
	{
		bool IsUsingInverseFunction { get; }

		TParam WithUsingInverseFunction(bool useInverse);
	}
}
