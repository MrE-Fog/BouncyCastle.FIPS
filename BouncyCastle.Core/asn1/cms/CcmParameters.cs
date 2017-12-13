using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class CcmParameters : Asn1Encodable
    {
        private readonly byte[] nonce;
        private readonly int mIicvLen;

        public static CcmParameters GetInstance(object obj)
        {
            if (obj is CcmParameters)
                return (CcmParameters)obj;

            if (obj != null)
                return new CcmParameters(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private CcmParameters(
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

        public CcmParameters(
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
