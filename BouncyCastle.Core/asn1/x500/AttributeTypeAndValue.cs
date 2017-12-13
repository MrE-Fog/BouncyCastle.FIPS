using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.X500
{
    /// <summary>
    /// Holding class for the AttributeTypeAndValue structures that make up an RDN.
    /// </summary>
    public class AttributeTypeAndValue : Asn1Encodable
    {
        private DerObjectIdentifier type;
        private Asn1Encodable value;

        private AttributeTypeAndValue(Asn1Sequence seq)
        {
            type = (DerObjectIdentifier)seq[0];
            value = (Asn1Encodable)seq[1];
        }

        public static AttributeTypeAndValue GetInstance(object o)
        {
            if (o is AttributeTypeAndValue)
            {
                return (AttributeTypeAndValue)o;
            }
            else if (o != null)
            {
                return new AttributeTypeAndValue(Asn1Sequence.GetInstance(o));
            }

            throw new ArgumentException("null value in getInstance()");
        }

        public AttributeTypeAndValue(
            DerObjectIdentifier type,
            Asn1Encodable value)
        {
            this.type = type;
            this.value = value;
        }

        public DerObjectIdentifier Type
        {
            get
            {
                return type;
            }
        }

        public Asn1Encodable Value
        {
            get
            {
                return value;
            }
        }

        /// <summary>
        /// AttributeTypeAndValue::= SEQUENCE {
        ///           type OBJECT IDENTIFIER,
        ///          value ANY DEFINED BY type
        ///   }
        /// </summary>
        /// <returns>A basic ASN.1 object representation.</returns>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(type);
            v.Add(value);

            return new DerSequence(v);
        }
    }
}
