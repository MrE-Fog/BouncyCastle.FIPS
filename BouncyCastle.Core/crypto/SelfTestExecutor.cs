using System;

namespace Org.BouncyCastle.Crypto
{
	public class SelfTestExecutor
	{
		internal static T Validate<T>(Algorithm algorithm, T engine, IBasicKatTest<T> test)
		{
			try
			{
				if (!test.HasTestPassed(engine))
				{
					CryptoStatus.MoveToErrorStatus(new SelfTestFailedError("Self test failed", algorithm));
				}

				return engine;
			}
			catch (Exception e)
			{
				CryptoStatus.MoveToErrorStatus(new SelfTestFailedError("Exception on self test: " + e.Message, algorithm));
			}

			return default(T); // we'll never get this far
		}

		internal static T Validate<T>(Algorithm algorithm, T engine, VariantKatTest<T> test)
		{
			try
			{
				test.Evaluate(engine);

				return engine;
			}
			catch (TestFailedException e)
			{
				CryptoStatus.MoveToErrorStatus(new SelfTestFailedError(e.Message, algorithm));
			}
			catch (Exception e)
			{
				CryptoStatus.MoveToErrorStatus(new SelfTestFailedError("Exception on self test: " + e.Message, algorithm));
			}

			return default(T); // we'll never get this far
		}

		internal static void Validate(Algorithm algorithm, VariantInternalKatTest test)
		{
			try
			{
				if (!algorithm.Equals(test.Algorithm))
				{
					throw new TestFailedException("Inconsistent algorithm tag for " + algorithm);
				}

				test.Evaluate();
			}
			catch (TestFailedException e)
			{
				CryptoStatus.MoveToErrorStatus(new SelfTestFailedError(e.Message, algorithm));
			}
			catch (Exception e)
			{
				CryptoStatus.MoveToErrorStatus(new SelfTestFailedError("Exception on self test: " + e.Message, algorithm));
			}
		}

		internal static T Validate<T>(Algorithm algorithm, T parameters, IConsistencyTest<T> test)
		{
			try
			{
				if (!test.HasTestPassed(parameters))
				{
					CryptoStatus.MoveToErrorStatus(new ConsistencyTestFailedError("Consistency test failed", algorithm));
				}

				return parameters;
			}
			catch (Exception e)
			{
				CryptoStatus.MoveToErrorStatus(new ConsistencyTestFailedError("Exception on consistency test: " + e.Message, algorithm));
			}

			return default(T); // we'll never get this far
		}

		internal class TestFailedException: Exception
		{
			public TestFailedException(String message): base(message)
			{
			}
		}
	}
}

