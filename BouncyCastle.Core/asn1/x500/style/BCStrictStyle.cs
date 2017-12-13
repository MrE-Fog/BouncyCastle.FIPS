using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    /**
     * Variation of BCStyle that insists on strict ordering for equality
     * and hashCode comparisons
     */
    public class BCStrictStyle: BCStyle
    {
        public static new readonly IX500NameStyle Instance = new BCStrictStyle();

        public override bool AreEqual(X500Name name1, X500Name name2)
        {
            Rdn[] rdns1 = name1.GetRdns();
            Rdn[] rdns2 = name2.GetRdns();

            if (rdns1.Length != rdns2.Length)
            {
                return false;
            }

            for (int i = 0; i != rdns1.Length; i++)
            {
                if (!RdnAreEqual(rdns1[i], rdns2[i]))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
