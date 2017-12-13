using System;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    public class OriginatorInformation
    {
        private OriginatorInfo originatorInfo;

        public OriginatorInformation(OriginatorInfo originatorInfo)
        {
            this.originatorInfo = originatorInfo;
        }

        internal OriginatorInfo ToAsn1Structure()
        {
            return originatorInfo;
        }
    }
}