using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Utilities
{
    /// <summary>
    /// Builder and holder class for preparing SP 800-56A/56B compliant MacData. Elements in the data are copied in
    /// directly as byte arrays.
    /// </summary>
    public sealed class ByteMacData
    {
        /// <summary>
        /// Standard type strings for the headers of KAS/KTS MAC calculations.
        /// </summary>
        public class Type
        {
            public static readonly Type UNILATERALU = new Type("KC_1_U");
            public static readonly Type UNILATERALV = new Type("KC_1_V");
            public static readonly Type BILATERALU = new Type("KC_2_U");
            public static readonly Type BILATERALV = new Type("KC_2_V");

            private readonly string enc;

            Type(string enc)
            {
                this.enc = enc;
            }

            public byte[] GetHeader()
            {
                return Strings.ToByteArray(enc);
            }
        }

        /// <summary>
        /// Builder to create OtherInfo
        /// </summary>
        public class Builder
        {
            private readonly Type type;

            private byte[] idU;
            private byte[] idV;
            private byte[] ephemDataU;
            private byte[] ephemDataV;
            private byte[] text;

            /// <summary>
            /// Create a basic builder with just the compulsory fields.
            /// </summary>
            /// <param name="type">the MAC header</param>
            /// <param name="idU">sender party ID.</param>
            /// <param name="idV">receiver party ID.</param>
            /// <param name="ephemDataU">ephemeral data from sender.</param>
            /// <param name="ephemDataV">ephemeral data from receiver.</param>
            public Builder(Type type, byte[] idU, byte[] idV, byte[] ephemDataU, byte[] ephemDataV)
            {
                this.type = type;
                this.idU = Arrays.Clone(idU);
                this.idV = Arrays.Clone(idV);
                this.ephemDataU = Arrays.Clone(ephemDataU);
                this.ephemDataV = Arrays.Clone(ephemDataV);
            }

            /// <summary>
            /// Add optional text.
            /// </summary>
            /// <param name="text">optional agreed text to add to the MAC.</param>
            /// <returns>the current builder instance.</returns>
            public Builder WithText(byte[] text)
            {
                this.text = toByteArray(new DerTaggedObject(false, 0, getOctetString(text)));

                return this;
            }

            /// <summary>
            /// Build the MacData from the inputs.
            /// </summary>
            /// <returns></returns>
            public ByteMacData Build()
            {
                if (type.Equals(Type.UNILATERALU) || type.Equals(Type.BILATERALU))
                {
                    return new ByteMacData(concatenate(type.GetHeader(), idU, idV, ephemDataU, ephemDataV, text));
                }
                else if (type.Equals(Type.UNILATERALV) || type.Equals(Type.BILATERALV))
                {
                    return new ByteMacData(concatenate(type.GetHeader(), idV, idU, ephemDataV, ephemDataU, text));
                }
                else
                {
                    throw new InvalidOperationException("Unknown type encountered in build");   // should never happen
                }
            }

            private byte[] concatenate(byte[] header, byte[] id1, byte[] id2, byte[] ed1, byte[] ed2, byte[] text)
            {
                return Arrays.ConcatenateAll(header, id1, id2, ed1, ed2, text);
            }
        }

        private readonly byte[] macData;

        private ByteMacData(byte[] macData)
        {
            this.macData = macData;
        }

        public byte[] GetMacData()
        {
            return Arrays.Clone(macData);
        }

        static Asn1OctetString getOctetString(byte[] data)
        {
            if (data == null)
            {
                return new DerOctetString(new byte[0]);
            }

            return new DerOctetString(Arrays.Clone(data));
        }

        static byte[] toByteArray(Asn1Object primitive)
        {
            try
            {
                return primitive.GetEncoded();
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("Cannot get encoding: " + e.Message, e);
            }
        }
    }
}
