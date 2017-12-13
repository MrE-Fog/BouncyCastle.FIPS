using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto
{
    public class IllegalKeyException : Exception
    {
        public IllegalKeyException(string message) : base(message)
        {
        }
    }
}
