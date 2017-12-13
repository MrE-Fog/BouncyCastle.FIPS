using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class GcmParameters : Asn1Encodable
    {
        private readonly byte[] nonce;
        private readonly int mIicvLen;

        public static GcmParameters GetInstance(object obj)
        {
            if (obj is GcmParameters)
                return (GcmParameters)obj;

            if (obj != null)
                return new GcmParameters(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private GcmParameters(
            Asn1Sequence seq)
        {
            this.nonce = Asn1OctetString.GetInstance(seq[0]).GetOctets();

            if (seq.Count == 2)
            {
                this.mIicvLen = DerInteger.GetInstance(seq[1]).Value.IntValue;
            }
            else
            {
                this.mIicvLen = 12;
            }
        }

        public GcmParameters(
            byte[] nonce,
            int icvLen)
        {
            this.nonce = Arrays.Clone(nonce);
            this.mIicvLen = icvLen;
        }

        public byte[] GetNonce()
        {
            return Arrays.Clone(nonce);
        }

        public int IcvLen
        {
            get
            {
                return mIicvLen;
            }
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(new DerOctetString(nonce));

            if (mIicvLen != 12)
            {
                v.Add(new DerInteger(mIicvLen));
            }

            return new DerSequence(v);
        }
    }
}
