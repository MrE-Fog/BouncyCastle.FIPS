using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto
{
    public class MaxBytesExceededException: Exception
    {
        internal MaxBytesExceededException(String msg): base(msg)
        {

        }
    }
}
