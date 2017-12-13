using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Fips
{
    public class FipsKdfAlgorithm: KdfAlgorithm
    {
        internal FipsKdfAlgorithm(FipsAlgorithm kdfAlgorithm, FipsPrfAlgorithm prfAlgorithm):base(kdfAlgorithm, prfAlgorithm)
        {
        }

        internal FipsKdfAlgorithm(FipsKdfAlgorithm kdfAlg, FipsPrfAlgorithm prfAlgorithm) : base((FipsAlgorithm)kdfAlg.Kdf, prfAlgorithm)
        {

        }
    }
}
