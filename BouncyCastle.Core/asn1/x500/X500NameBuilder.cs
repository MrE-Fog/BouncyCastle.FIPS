using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.X500
{
    /// <summary>
    /// A builder class for making X.500 Name objects.
    /// </summary>
    public class X500NameBuilder
    {
        private IX500NameStyle template;
        private IList rdns = Platform.CreateArrayList();

        /// <summary>
        /// Constructor using the default style (BCStyle).
        /// </summary>
        public X500NameBuilder(): this(BCStyle.Instance)
        {    
        }

        /// <summary>
        /// Constructor using a specified style.
        /// </summary>
        /// <param name="template">The style template for string to DN conversion.</param>
        public X500NameBuilder(IX500NameStyle template)
        {
            this.template = template;
        }

        /// <summary>
        /// Add an RDN based on a single OID and a string representation of its value.
        /// </summary>
        /// <param name="oid">The OID for this RDN.</param>
        /// <param name="value">The string representation of the value the OID refers to.</param>
        /// <returns>The current builder instance.</returns>
        public X500NameBuilder AddRdn(DerObjectIdentifier oid, String value)
        {
            this.AddRdn(oid, template.StringToValue(oid, value));

            return this;
        }

        /// <summary>
        /// Add an RDN based on a single OID and an ASN.1 value.
        /// </summary>
        /// <param name="oid">The OID for this RDN.</param>
        /// <param name="value">The ASN.1 value the OID refers to.</param>
        /// <returns>The current builder instance.</returns>
        public X500NameBuilder AddRdn(DerObjectIdentifier oid, Asn1Encodable value)
        {
            rdns.Add(new Rdn(oid, value));

            return this;
        }

        /// <summary>
        /// Add an RDN based on the passed in AttributeTypeAndValue.
        /// </summary>
        /// <param name="attrTAndV">the AttributeTypeAndValue to build the RDN from.</param>
        /// <returns>The current builder instance.</returns>
        public X500NameBuilder AddRdn(AttributeTypeAndValue attrTAndV)
        {
            rdns.Add(new Rdn(attrTAndV));

            return this;
        }

        /// <summary>
        /// Add a multi-valued RDN made up of the passed in OIDs and associated string values.
        /// </summary>
        /// <param name="oids">The OIDs making up the RDN.</param>
        /// <param name="values">The string representation of the values the OIDs refer to.</param>
        /// <returns>The current builder instance.</returns>
        public X500NameBuilder AddMultiValuedRdn(DerObjectIdentifier[] oids, String[] values)
        {
            Asn1Encodable[] vals = new Asn1Encodable[values.Length];

            for (int i = 0; i != vals.Length; i++)
            {
                vals[i] = template.StringToValue(oids[i], values[i]);
            }

            return AddMultiValuedRdn(oids, vals);
        }

        /// <summary>
        /// Add a multi-valued RDN made up of the passed in OIDs and associated ASN.1 values.
        /// </summary>
        /// <param name="oids">The OIDs making up the RDN.</param>
        /// <param name="values">The ASN.1 values the OIDs refer to.</param>
        /// <returns>The current builder instance.</returns>
        public X500NameBuilder AddMultiValuedRdn(DerObjectIdentifier[] oids, Asn1Encodable[] values)
        {
            AttributeTypeAndValue[] avs = new AttributeTypeAndValue[oids.Length];

            for (int i = 0; i != oids.Length; i++)
            {
                avs[i] = new AttributeTypeAndValue(oids[i], values[i]);
            }

            return AddMultiValuedRdn(avs);
        }

        /// <summary>
        /// Add an RDN based on the passed in AttributeTypeAndValues.
        /// </summary>
        /// <param name="attrTAndVs">The AttributeTypeAndValues to build the RDN from.</param>
        /// <returns>The current builder instance.</returns>
        public X500NameBuilder AddMultiValuedRdn(AttributeTypeAndValue[] attrTAndVs)
        {
            rdns.Add(new Rdn(attrTAndVs));

            return this;
        }

        /// <summary>
        /// Build an X.500 name for the current builder state.
        /// </summary>
        /// <returns>A new X.500 name.</returns>
        public X500Name Build()
        {
            Rdn[] vals = new Rdn[rdns.Count];

            for (int i = 0; i != vals.Length; i++)
            {
                vals[i] = (Rdn)rdns[i];
            }

            return new X500Name(template, vals);
        }
    }
}
