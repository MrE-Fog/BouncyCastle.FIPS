using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base error class for operational errors.
    /// </summary>
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE)
[Serializable]
#endif
	public class CryptoOperationError
        : Exception
	{
		public CryptoOperationError()
		{
		}

		public CryptoOperationError(string message)
            : base(message)
		{
		}

        public CryptoOperationError(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}

