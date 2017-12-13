using System;

namespace Org.BouncyCastle.Crypto
{
	internal abstract class VariantKatTest<T>
	{
		protected void Fail(String message)
		{
			throw new SelfTestExecutor.TestFailedException(message);
		}

		internal abstract void Evaluate(T engine);
	}
}

