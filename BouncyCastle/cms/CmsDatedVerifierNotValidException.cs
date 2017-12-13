using System;

namespace Org.BouncyCastle.Cms
{
    [Serializable]
    internal class CmsDatedVerifierNotValidException : CmsException
    {
        public CmsDatedVerifierNotValidException()
        {
        }

        public CmsDatedVerifierNotValidException(string message) : base(message)
        {
        }

        public CmsDatedVerifierNotValidException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}