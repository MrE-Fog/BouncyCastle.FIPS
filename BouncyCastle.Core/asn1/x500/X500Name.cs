using Org.BouncyCastle.Asn1.X500.Style;
using System;
using System.Collections;

#if SILVERLIGHT || PORTABLE
using System.Collections.Generic;
#endif

namespace Org.BouncyCastle.Asn1.X500
{

    /**
     * The X.500 Name object.
     * <pre>
     *     Name ::= CHOICE {
     *                       RDNSequence }
     *
     *     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     *
     *     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
     *
     *     AttributeTypeAndValue ::= SEQUENCE {
     *                                   type  OBJECT IDENTIFIER,
     *                                   value ANY }
     * </pre>
     */
    public class X500Name : Asn1Encodable, IAsn1Choice
    {
        private static IX500NameStyle defaultStyle = BCStyle.Instance;

        private bool isHashCodeCalculated;
        private int hashCodeValue;

        private IX500NameStyle style;
        private Rdn[] rdns;

        /**
         * Return a X500Name based on the passed in tagged object.
         * 
         * @param obj tag object holding name.
         * @param explicit true if explicitly tagged false otherwise.
         * @return the X500Name
         */
        public static X500Name GetInstance(
            Asn1TaggedObject obj,
            bool isExplicit)
        {
            // must be true as choice item
            return GetInstance(Asn1Sequence.GetInstance(obj, true));
        }

        public static X500Name GetInstance(
            object obj)
        {
            if (obj is X500Name)
            {
                return (X500Name)obj;
            }
            else if (obj != null)
            {
                return new X500Name(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        public static X500Name GetInstance(
            IX500NameStyle style,
            Object obj)
        {
            if (obj is X500Name)
            {
                return new X500Name(style, (X500Name)obj);
            }
            else if (obj != null)
            {
                return new X500Name(style, Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        /**
         * Constructor from ASN1Sequence
         *
         * the principal will be a list of constructed sets, each containing an (OID, String) pair.
         */
        private X500Name(
            Asn1Sequence seq) : this(defaultStyle, seq)
        {
        }

        private X500Name(IX500NameStyle style, X500Name name)
        {
            this.rdns = name.rdns;
            this.style = style;
        }

        private X500Name(
            IX500NameStyle style,
            Asn1Sequence seq)
        {
            this.style = style;
            this.rdns = new Rdn[seq.Count];

            int index = 0;

            for (IEnumerator e = seq.GetEnumerator(); e.MoveNext();)
            {
                rdns[index++] = Rdn.GetInstance(e.Current);
            }
        }

        public X500Name(
            Rdn[] rDNs) : this(defaultStyle, rDNs)
        {

        }

        public X500Name(
            IX500NameStyle style,
            Rdn[] rDNs)
        {
            this.rdns = rDNs;
            this.style = style;
        }

        public X500Name(
            string dirName) : this(defaultStyle, dirName)
        {

        }

        public X500Name(
            IX500NameStyle style,
            String dirName) : this(style.FromString(dirName))
        {
            this.style = style;
        }

        /**
         * return an array of RDNs in structure order.
         *
         * @return an array of RDN objects.
         */
        public Rdn[] GetRdns()
        {
            Rdn[] tmp = new Rdn[this.rdns.Length];

            Array.Copy(rdns, 0, tmp, 0, tmp.Length);

            return tmp;
        }

        /**
         * return an array of OIDs contained in the attribute type of each RDN in structure order.
         *
         * @return an array, possibly zero length, of DerObjectIdentifiers objects.
         */
        public DerObjectIdentifier[] GetAttributeTypes()
        {
            int count = 0;

            for (int i = 0; i != rdns.Length; i++)
            {
                Rdn rdn = rdns[i];

                count += rdn.Count;
            }

            DerObjectIdentifier[] res = new DerObjectIdentifier[count];

            count = 0;

            for (int i = 0; i != rdns.Length; i++)
            {
                Rdn rdn = rdns[i];

                if (rdn.IsMultiValued)
                {
                    AttributeTypeAndValue[] attr = rdn.GetTypesAndValues();
                    for (int j = 0; j != attr.Length; j++)
                    {
                        res[count++] = attr[j].Type;
                    }
                }
                else if (rdn.Count != 0)
                {
                    res[count++] = rdn.First.Type;
                }
            }

            return res;
        }

        /**
         * return an array of RDNs containing the attribute type given by OID in structure order.
         *
         * @param attributeType the type OID we are looking for.
         * @return an array, possibly zero length, of RDN objects.
         */
        public Rdn[] GetRdns(DerObjectIdentifier attributeType)
        {
            Rdn[] res = new Rdn[rdns.Length];
            int count = 0;

            for (int i = 0; i != rdns.Length; i++)
            {
                Rdn rdn = rdns[i];

                if (rdn.IsMultiValued)
                {
                    AttributeTypeAndValue[] attr = rdn.GetTypesAndValues();
                    for (int j = 0; j != attr.Length; j++)
                    {
                        if (attr[j].Type.Equals(attributeType))
                        {
                            res[count++] = rdn;
                            break;
                        }
                    }
                }
                else
                {
                    if (rdn.First.Type.Equals(attributeType))
                    {
                        res[count++] = rdn;
                    }
                }
            }

            Rdn[] tmp = new Rdn[count];

            Array.Copy(res, 0, tmp, 0, tmp.Length);

            return tmp;
        }

        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(rdns);
        }

        public int EquivalentHashCode()
        {
            if (isHashCodeCalculated)
            {
                return hashCodeValue;
            }

            isHashCodeCalculated = true;

            hashCodeValue = style.CalculateHashCode(this);

            return hashCodeValue;
        }

        /**
         * test for equality - note: case is ignored.
         */
        public bool Equivalent(object obj)
        {
            if (obj == this)
            {
                return true;
            }

            if (!(obj is X500Name || obj is Asn1Sequence))
            {
                return false;
            }

            Asn1Object derO = ((Asn1Encodable)obj).ToAsn1Object();

            if (this.ToAsn1Object().Equals(derO))
            {
                return true;
            }

            try
            {
                return style.AreEqual(this, new X500Name(Asn1Sequence.GetInstance(((Asn1Encodable)obj).ToAsn1Object())));
            }
            catch (Exception)
            {
                return false;
            }
        }

        public override string ToString()
        {
            return style.ToString(this);
        }

        /**
         * The current default style.
         *
         * @return default style for X500Name construction.
         */
        public static IX500NameStyle DefaultStyle
        {
            get
            {
                return defaultStyle;
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentException("cannot set style to null");
                }

                defaultStyle = value;
            }
        }
    }

}
