using System;

namespace Org.BouncyCastle.Security
{ 
    internal class GeneralModeContext
        : SecurityContext
    {
        internal override bool IsApprovedOnlyMode
        {
            get { return false; }
        }
    }
}
