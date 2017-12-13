using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities.Test
{
    public class TestRandomData : FixedSecureRandom
    {
        /**
         * Constructor from a Hex encoding of the data.
         *
         * @param encoding a Hex encoding of the data to be returned.
         */
        public TestRandomData(String encoding) : base(new FixedSecureRandom.Data(Hex.Decode(encoding)))
        {
        }

        /**
         * Constructor from an array of bytes.
         *
         * @param encoding a byte array representing the data to be returned.
         */
        public TestRandomData(byte[] encoding) : base(new FixedSecureRandom.Data(encoding))
        {
        }
    }
}
