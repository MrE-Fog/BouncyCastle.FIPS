using System;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// This exception is thrown whenever we find something we don't expect in a message
	/// </summary>
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE)
	[Serializable]
#endif
	public class InvalidCipherTextException
		: CryptoException
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		public InvalidCipherTextException()
		{
		}

		/// <summary>
		/// Create a InvalidCipherTextException with the given message.
		/// </summary>
		/// <param name="message">The message to be carried with the exception.</param>
		public InvalidCipherTextException(
			string message)
			: base(message)
		{
		}

		/// <summary>
		/// Create a InvalidCipherTextException with the given message and underlying cause.
		/// </summary>
		/// <param name="message">The message to be carried with the exception.</param>
		/// <param name="exception">The exception that caused this exception to be raised.</param>
		public InvalidCipherTextException(
			string		message,
			Exception	exception)
			: base(message, exception)
		{
		}
	}
}
