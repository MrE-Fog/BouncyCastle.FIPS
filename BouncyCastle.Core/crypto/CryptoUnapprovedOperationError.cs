using System;

namespace Org.BouncyCastle.Crypto
{
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE)
    [Serializable]
#endif
    public class CryptoUnapprovedOperationError: Exception
	{
		public CryptoUnapprovedOperationError (string message): base(message)
		{
		}

		public CryptoUnapprovedOperationError (string message, Algorithm algorithm): base(message + ": " + algorithm.Name + (algorithm.Mode != AlgorithmMode.NONE ? "/" + algorithm.Mode : ""))
		{
		}
	}
}

