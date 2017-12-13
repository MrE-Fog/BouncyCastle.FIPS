using System;

namespace Org.BouncyCastle.Asn1.X500
{
    public class Rdn : Asn1Encodable
    {
        private Asn1Set values;

        private Rdn(Asn1Set values)
        {
            this.values = values;
        }

        public static Rdn GetInstance(object obj)
        {
            if (obj is Rdn)
            {
                    return (Rdn)obj;
            }
            else if (obj != null)
            {
                return new Rdn(Asn1Set.GetInstance(obj));
            }

            return null;
        }

        /**
         * Create a single valued RDN.
         *
         * @param oid RDN type.
         * @param value RDN value.
         */
        public Rdn(DerObjectIdentifier oid, Asn1Encodable value)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(oid);
            v.Add(value);

            this.values = new DerSet(new DerSequence(v));
        }

        public Rdn(AttributeTypeAndValue attrTAndV)
        {
            this.values = new DerSet(attrTAndV);
        }

        /**
         * Create a multi-valued RDN.
         *
         * @param aAndVs attribute type/value pairs making up the RDN
         */
        public Rdn(AttributeTypeAndValue[] aAndVs)
        {
            this.values = new DerSet(aAndVs);
        }

        public bool IsMultiValued
        { 
            get {
                return this.values.Count > 1;
            }
        }

        /**
         * Return the number of AttributeTypeAndValue objects in this RDN,
         *
         * @return size of RDN, greater than 1 if multi-valued.
         */
        public int Count
        {
            get
            {
                return this.values.Count;
            }
        }

        public AttributeTypeAndValue First
        {
            get
            {
                if (this.values.Count == 0)
                {
                    return null;
                }

                return AttributeTypeAndValue.GetInstance(this.values[0]);
            }
        }

        public AttributeTypeAndValue[] GetTypesAndValues()
        {
            AttributeTypeAndValue[] tmp = new AttributeTypeAndValue[values.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = AttributeTypeAndValue.GetInstance(values[i]);
            }

            return tmp;
        }

        /**
         * <pre>
         * RelativeDistinguishedName ::=
         *                     SET OF AttributeTypeAndValue
         *
         * AttributeTypeAndValue ::= SEQUENCE {
         *        type     AttributeType,
         *        value    AttributeValue }
         * </pre>
         * @return this object as its ASN1Primitive type
         */
        public override Asn1Object ToAsn1Object()
        {
            return values;
        }
    }
}
