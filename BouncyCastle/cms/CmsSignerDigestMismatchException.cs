using System;

namespace Org.BouncyCastle.Cms
{
    [Serializable]
    internal class CmsSignerDigestMismatchException : CmsException
    {
        public CmsSignerDigestMismatchException()
        {
        }

        public CmsSignerDigestMismatchException(string message) : base(message)
        {
        }

        public CmsSignerDigestMismatchException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}