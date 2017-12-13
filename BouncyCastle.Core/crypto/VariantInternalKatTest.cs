using System;

namespace Org.BouncyCastle.Crypto
{
	internal abstract class VariantInternalKatTest
	{
		protected readonly Algorithm algorithm;

		protected VariantInternalKatTest(Algorithm algorithm)
		{
			this.algorithm = algorithm;
		}

		protected void Fail(String message)
		{
			throw new SelfTestExecutor.TestFailedException(message);
		}

		internal Algorithm Algorithm
		{
			get {
				return algorithm;
			}
		}

		internal abstract void Evaluate();
	}
}

