
using System;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class CrlBag : Asn1Encodable
    {
        private DerObjectIdentifier crlId;
        private Asn1Encodable crlValue;

        private CrlBag(
            Asn1Sequence seq)
        {
            this.crlId = (DerObjectIdentifier)seq[0];
            this.crlValue = ((Asn1TaggedObject)seq[1]).GetObject();
        }

        public static CrlBag GetInstance(Object o)
        {
            if (o is CrlBag)
            {
                return (CrlBag)o;
            }
            else if (o != null)
            {
                return new CrlBag(Asn1Sequence.GetInstance(o));
            }

            return null;
        }

        public CrlBag(
            DerObjectIdentifier crlId,
            Asn1Encodable crlValue)
        {
            this.crlId = crlId;
            this.crlValue = crlValue;
        }

        public DerObjectIdentifier CrlId
        {
            get
            {
                return crlId;
            }
        }

        public Asn1Encodable CrlValue
        {
            get
            {
                return crlValue;
            }
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(crlId);
            v.Add(new DerTaggedObject(0, crlValue));

            return new DerSequence(v);
        }
    }
}
