using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    public class IetfUtils
    {
        private static string unescape(string elt)
        {
            if (elt.Length == 0 || (elt.IndexOf('\\') < 0 && elt.IndexOf('"') < 0))
            {
                return elt.Trim();
            }

            char[] elts = elt.ToCharArray();
            bool escaped = false;
            bool quoted = false;
            StringBuilder buf = new StringBuilder(elt.Length);
            int start = 0;

            // if it's an escaped hash string and not an actual encoding in string form
            // we need to leave it escaped.
            if (elts[0] == '\\')
            {
                if (elts[1] == '#')
                {
                    start = 2;
                    buf.Append("\\#");
                }
            }

            bool nonWhiteSpaceEncountered = false;
            int lastEscaped = 0;
            char hex1 = (char)0;

            for (int i = start; i != elts.Length; i++)
            {
                char c = elts[i];

                if (c != ' ')
                {
                    nonWhiteSpaceEncountered = true;
                }

                if (c == '"')
                {
                    if (!escaped)
                    {
                        quoted = !quoted;
                    }
                    else
                    {
                        buf.Append(c);
                    }
                    escaped = false;
                }
                else if (c == '\\' && !(escaped || quoted))
                {
                    escaped = true;
                    lastEscaped = buf.Length;
                }
                else
                {
                    if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
                    {
                        continue;
                    }
                    if (escaped && isHexDigit(c))
                    {
                        if (hex1 != 0)
                        {
                            buf.Append((char)(convertHex(hex1) * 16 + convertHex(c)));
                            escaped = false;
                            hex1 = (char)0;
                            continue;
                        }
                        hex1 = c;
                        continue;
                    }
                    buf.Append(c);
                    escaped = false;
                }
            }

            if (buf.Length > 0)
            {
                while (buf[buf.Length - 1] == ' ' && lastEscaped != (buf.Length - 1))
                {
                    buf.Length = (buf.Length - 1);
                }
            }

            return buf.ToString();
        }

        private static bool isHexDigit(char c)
        {
            return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
        }

        private static int convertHex(char c)
        {
            if ('0' <= c && c <= '9')
            {
                return c - '0';
            }
            if ('a' <= c && c <= 'f')
            {
                return c - 'a' + 10;
            }
            return c - 'A' + 10;
        }

        public static Rdn[] rDNsFromString(String name, IX500NameStyle x500Style)
        {
            X500NameTokenizer nTok = new X500NameTokenizer(name);
            X500NameBuilder builder = new X500NameBuilder(x500Style);

            while (nTok.hasMoreTokens())
            {
                String token = nTok.nextToken();

                if (token.IndexOf('+') > 0)
                {
                    X500NameTokenizer pTok = new X500NameTokenizer(token, '+');
                    X500NameTokenizer vTok = new X500NameTokenizer(pTok.nextToken(), '=');

                    String attr = vTok.nextToken();

                    if (!vTok.hasMoreTokens())
                    {
                        throw new ArgumentException("badly formatted directory string");
                    }

                    String value = vTok.nextToken();
                    DerObjectIdentifier oid = x500Style.AttrNameToOID(attr.Trim());

                    if (pTok.hasMoreTokens())
                    {
                        IList oids = Platform.CreateArrayList();
                        IList values = Platform.CreateArrayList();

                        oids.Add(oid);
                        values.Add(unescape(value));

                        while (pTok.hasMoreTokens())
                        {
                            vTok = new X500NameTokenizer(pTok.nextToken(), '=');

                            attr = vTok.nextToken();

                            if (!vTok.hasMoreTokens())
                            {
                                throw new ArgumentException("badly formatted directory string");
                            }

                            value = vTok.nextToken();
                            oid = x500Style.AttrNameToOID(attr.Trim());


                            oids.Add(oid);
                            values.Add(unescape(value));
                        }

                        builder.AddMultiValuedRdn(toOIDArray(oids), toValueArray(values));
                    }
                    else
                    {
                        builder.AddRdn(oid, unescape(value));
                    }
                }
                else
                {
                    X500NameTokenizer vTok = new X500NameTokenizer(token, '=');

                    String attr = vTok.nextToken();

                    if (!vTok.hasMoreTokens())
                    {
                        throw new ArgumentException("badly formatted directory string");
                    }

                    String value = vTok.nextToken();
                    DerObjectIdentifier oid = x500Style.AttrNameToOID(attr.Trim());

                    builder.AddRdn(oid, unescape(value));
                }
            }

            return builder.Build().GetRdns();
        }

        private static String[] toValueArray(IList values)
        {
            String[] tmp = new String[values.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = (String)values[i];
            }

            return tmp;
        }

        private static DerObjectIdentifier[] toOIDArray(IList oids)
        {
            DerObjectIdentifier[] tmp = new DerObjectIdentifier[oids.Count];

            for (int i = 0; i != tmp.Length; i++)
            {
                tmp[i] = (DerObjectIdentifier)oids[i];
            }

            return tmp;
        }

        public static string[] FindAttrNamesForOID(
            DerObjectIdentifier oid,
            IDictionary lookup)
        {
            int count = 0;
            for (IEnumerator en = lookup.Values.GetEnumerator(); en.MoveNext();)
            {
                if (oid.Equals(en.Current))
                {
                    count++;
                }
            }

            String[] aliases = new String[count];
            count = 0;

            for (IEnumerator en = lookup.Keys.GetEnumerator(); en.MoveNext();)
            {
                string key = (String)en.Current;
                if (oid.Equals(lookup[key]))
                {
                    aliases[count++] = key;
                }
            }

            return aliases;
        }

        public static DerObjectIdentifier DecodeAttrName(
            String name,
            IDictionary lookUp)
        {
            if (name.ToUpper().StartsWith("OID."))
            {
                return new DerObjectIdentifier(name.Substring(4));
            }
            else if (name[0] >= '0' && name[0] <= '9')
            {
                return new DerObjectIdentifier(name);
            }

            DerObjectIdentifier oid = (DerObjectIdentifier)lookUp[name.ToLower()];
            if (oid == null)
            {
                throw new ArgumentException("Unknown object id - " + name + " - passed to distinguished name");
            }

            return oid;
        }

        public static Asn1Encodable ValueFromHexString(
            string str,
            int off)
        {
            byte[] data = new byte[(str.Length - off) / 2];
            for (int index = 0; index != data.Length; index++)
            {
                char left = str[(index * 2) + off];
                char right = str[(index * 2) + off + 1];

                data[index] = (byte)((convertHex(left) << 4) | convertHex(right));
            }

            return Asn1Object.FromByteArray(data);
        }

        public static void AppendRdn(
            StringBuilder buf,
            Rdn rdn,
            IDictionary oidSymbols)
        {
            if (rdn.IsMultiValued)
            {
                AttributeTypeAndValue[] atv = rdn.GetTypesAndValues();
                bool firstAtv = true;

                for (int j = 0; j != atv.Length; j++)
                {
                    if (firstAtv)
                    {
                        firstAtv = false;
                    }
                    else
                    {
                        buf.Append('+');
                    }

                    IetfUtils.AppendTypeAndValue(buf, atv[j], oidSymbols);
                }
            }
            else
            {
                if (rdn.First != null)
                {
                    IetfUtils.AppendTypeAndValue(buf, rdn.First, oidSymbols);
                }
            }
        }

        public static void AppendTypeAndValue(
            StringBuilder buf,
            AttributeTypeAndValue typeAndValue,
            IDictionary oidSymbols)
        {
            string sym = (string)oidSymbols[typeAndValue.Type];

            if (sym != null)
            {
                buf.Append(sym);
            }
            else
            {
                buf.Append(typeAndValue.Type.Id);
            }

            buf.Append('=');

            buf.Append(ValueToString(typeAndValue.Value));
        }

        public static string ValueToString(Asn1Encodable value)
        {
            StringBuilder vBuf = new StringBuilder();

            if (value is IAsn1String && !(value is DerUniversalString))
            {
                String v = ((IAsn1String)value).GetString();
                if (v.Length > 0 && v[0] == '#')
                {
                    vBuf.Append("\\" + v);
                }
                else
                {
                    vBuf.Append(v);
                }
            }
            else
            {
                try
                {
                    vBuf.Append("#" + bytesToString(Hex.Encode(value.ToAsn1Object().GetEncoded("DER"))));
                }
                catch (IOException)
                {
                    throw new ArgumentException("Other value has no encoded form");
                }
            }

            int end = vBuf.Length;
            int index = 0;

            if (vBuf.Length >= 2 && vBuf[0] == '\\' && vBuf[1] == '#')
            {
                index += 2;
            }

            while (index != end)
            {
                if ((vBuf[index] == ',')
                   || (vBuf[index] == '"')
                   || (vBuf[index] == '\\')
                   || (vBuf[index] == '+')
                   || (vBuf[index] == '=')
                   || (vBuf[index] == '<')
                   || (vBuf[index] == '>')
                   || (vBuf[index] == ';'))
                {
                    vBuf.Insert(index, "\\");
                    index++;
                    end++;
                }

                index++;
            }

            int start = 0;
            if (vBuf.Length > 0)
            {
                while (vBuf.Length > start && vBuf[start] == ' ')
                {
                    vBuf.Insert(start, "\\");
                    start += 2;
                }
            }

            int endBuf = vBuf.Length - 1;

            while (endBuf >= 0 && vBuf[endBuf] == ' ')
            {
                vBuf.Insert(endBuf, '\\');
                endBuf--;
            }

            return vBuf.ToString();
        }

        private static String bytesToString(
            byte[] data)
        {
            char[] cs = new char[data.Length];

            for (int i = 0; i != cs.Length; i++)
            {
                cs[i] = (char)(data[i] & 0xff);
            }

            return new String(cs);
        }

        public static string Canonicalize(string s)
        {
            string value = s.ToLower();

            if (value.Length > 0 && value[0] == '#')
            {
                Asn1Object obj = decodeObject(value);

                if (obj is IAsn1String)
                {
                    value = ((IAsn1String)obj).GetString();
                }
            }

            if (value.Length > 1)
            {
                int start = 0;
                while (start + 1 < value.Length && value[start] == '\\' && value[start + 1] == ' ')
                {
                    start += 2;
                }

                int end = value.Length - 1;
                while (end - 1 > 0 && value[end - 1] == '\\' && value[end] == ' ')
                {
                    end -= 2;
                }

                if (start > 0 || end < value.Length - 1)
                {
                    value = value.Substring(start, end + 1 - start);
                }
            }

            value = stripInternalSpaces(value);

            return value;
        }

        private static Asn1Object decodeObject(string oValue)
        {
            try
            {
                return Asn1Object.FromByteArray(Hex.Decode(oValue.Substring(1)));
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unknown encoding in name: " + e);
            }
        }

        public static String stripInternalSpaces(
            String str)
        {
            StringBuilder res = new StringBuilder();

            if (str.Length != 0)
            {
                char c1 = str[0];

                res.Append(c1);

                for (int k = 1; k < str.Length; k++)
                {
                    char c2 = str[k];
                    if (!(c1 == ' ' && c2 == ' '))
                    {
                        res.Append(c2);
                    }
                    c1 = c2;
                }
            }

            return res.ToString();
        }

        public static bool RdnAreEqual(Rdn rdn1, Rdn rdn2)
        {
            if (rdn1.IsMultiValued)
            {
                if (rdn2.IsMultiValued)
                {
                    AttributeTypeAndValue[] atvs1 = rdn1.GetTypesAndValues();
                    AttributeTypeAndValue[] atvs2 = rdn2.GetTypesAndValues();

                    if (atvs1.Length != atvs2.Length)
                    {
                        return false;
                    }

                    for (int i = 0; i != atvs1.Length; i++)
                    {
                        if (!atvAreEqual(atvs1[i], atvs2[i]))
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                if (!rdn2.IsMultiValued)
                {
                    return atvAreEqual(rdn1.First, rdn2.First);
                }
                else
                {
                    return false;
                }
            }

            return true;
        }

        private static bool atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2)
        {
            if (atv1 == atv2)
            {
                return true;
            }

            if (atv1 == null)
            {
                return false;
            }

            if (atv2 == null)
            {
                return false;
            }

            DerObjectIdentifier o1 = atv1.Type;
            DerObjectIdentifier o2 = atv2.Type;

            if (!o1.Equals(o2))
            {
                return false;
            }

            String v1 = IetfUtils.Canonicalize(IetfUtils.ValueToString(atv1.Value));
            String v2 = IetfUtils.Canonicalize(IetfUtils.ValueToString(atv2.Value));

            if (!v1.Equals(v2))
            {
                return false;
            }

            return true;
        }
    }
}
