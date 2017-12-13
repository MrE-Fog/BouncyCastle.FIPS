using System;

namespace Org.BouncyCastle.Security
{
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE)
    [Serializable]
#endif
    public class InvalidSignatureException : GeneralSecurityException
    {
        public InvalidSignatureException(string message) : base(message)
        {
        }
    }
}
