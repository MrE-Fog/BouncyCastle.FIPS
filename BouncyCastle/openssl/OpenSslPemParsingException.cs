using System;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
    public class OpenSslPemParsingException : IOException
    {
        public OpenSslPemParsingException(String message) : base(message)
        {
        }

        public OpenSslPemParsingException(String message, Exception underlying) : base(message, underlying)
        {
        }
    }
}
