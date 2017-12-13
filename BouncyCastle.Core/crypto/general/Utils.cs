using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.General
{ 
    internal class Utils
    {
        internal static void ApprovedModeCheck(String type, Algorithm algorithm)
        {
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError(type + " unavailable in approved mode: " + algorithm.Name);
            }
        }
    }
}
