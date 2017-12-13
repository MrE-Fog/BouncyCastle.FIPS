using System;

namespace Org.BouncyCastle.Security
{
    internal class FipsModeContext
        : SecurityContext
    {
        internal override bool IsApprovedOnlyMode
        {
            get { return true; }
        }
    }
}
