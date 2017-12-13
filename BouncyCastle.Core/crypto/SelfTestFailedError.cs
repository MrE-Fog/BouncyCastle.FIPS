using System;

namespace Org.BouncyCastle.Crypto
{
	public class SelfTestFailedError: CryptoOperationError
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="message">A message describing the error.</param>
		/// <param name="algorithm">The algorithm the failure was for.</param>
		public SelfTestFailedError(String message, Algorithm algorithm): base(message + ": " + algorithm.Name)
		{
		}
	}
}

