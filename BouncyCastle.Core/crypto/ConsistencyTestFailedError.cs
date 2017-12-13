using System;

namespace Org.BouncyCastle.Crypto
{
	public class ConsistencyTestFailedError: CryptoOperationError
	{
		public ConsistencyTestFailedError (string message): base(message)
		{
		}

		public ConsistencyTestFailedError (string message, Algorithm algorithm): base(message + ": " + algorithm.Name)
		{
		}
	}
}

