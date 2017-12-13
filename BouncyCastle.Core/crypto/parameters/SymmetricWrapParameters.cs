using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public abstract class SymmetricWrapParameters<TParam, TAlg>:ParametersWithIV<TParam, TAlg>, ISymmetricWrapParameters<TParam, TAlg> where TParam: IParameters<TAlg> where TAlg: Algorithm
	{
		private readonly bool useInverse;

		internal SymmetricWrapParameters(TAlg algorithm, bool useInverse, byte[] iv): base(algorithm, DefaultIVSize(algorithm), iv)
		{
			this.useInverse = useInverse;
		}

		public bool IsUsingInverseFunction {
			get {
				return useInverse;
			}
		}

		internal byte[] CreateDefaultIvIfNecessary(SecureRandom random)
		{
			if (Algorithm.Mode == AlgorithmMode.WRAP) {
				byte[] iv = new byte[8];

				random.NextBytes (iv);

				return iv;
			} else if (Algorithm.Mode == AlgorithmMode.WRAPPAD) {
				byte[] iv = new byte[4];

				random.NextBytes (iv);

				return iv;
			}

			return null;
		}

		public TParam WithUsingInverseFunction(bool useInverse)
		{
			return CreateParameter(Algorithm, useInverse, GetIV());
		}
			
		internal override TParam CreateParameter(TAlg algorithm, byte[] iv)
		{
			return CreateParameter(algorithm, IsUsingInverseFunction, iv);
		}

		internal abstract TParam CreateParameter(TAlg algorithm, bool useInverse, byte[] iv);

		static int DefaultIVSize(Algorithm algorithm)
		{
			if (algorithm.Mode == AlgorithmMode.WRAP) {
				return 8;
			} else if (algorithm.Mode == AlgorithmMode.WRAPPAD) {
				return 4;
			}

			return 0;
		}
	}
}

