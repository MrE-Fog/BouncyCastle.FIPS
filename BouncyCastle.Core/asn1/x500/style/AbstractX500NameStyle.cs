using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    /**
     * This class provides some default behavior and common implementation for a
     * X500NameStyle. It should be easily extendable to support implementing the
     * desired X500NameStyle.
     */
    public abstract class AbstractX500NameStyle: IX500NameStyle
    {

    /**
     * Tool function to shallow copy a Hashtable.
     *
     * @param paramsMap table to copy
     * @return the copy of the table
     */
    public static IDictionary CopyHashTable(IDictionary paramsMap)
    {
        IDictionary newTable = Platform.CreateHashtable();

        IEnumerator keys = paramsMap.Keys.GetEnumerator();
        while (keys.MoveNext())
        {
            Object key = keys.Current;
            newTable.Add(key, paramsMap[key]);
        }

        return newTable;
    }

    private int calcHashCode(Asn1Encodable enc)
    {
        String value = IetfUtils.ValueToString(enc);
        value = IetfUtils.Canonicalize(value);
        return value.GetHashCode();
    }

    public int CalculateHashCode(X500Name name)
    {
        int hashCodeValue = 0;
        Rdn[] rdns = name.GetRdns();

        // this needs to be order independent, like equals
        for (int i = 0; i != rdns.Length; i++)
        {
            if (rdns[i].IsMultiValued)
            {
                AttributeTypeAndValue[] atv = rdns[i].GetTypesAndValues();

                for (int j = 0; j != atv.Length; j++)
                {
                    hashCodeValue ^= atv[j].Type.GetHashCode();
                    hashCodeValue ^= calcHashCode(atv[j].Value);
                }
            }
            else
            {
                hashCodeValue ^= rdns[i].First.Type.GetHashCode();
                hashCodeValue ^= calcHashCode(rdns[i].First.Value);
            }
        }

        return hashCodeValue;
    }


    /**
     * For all string values starting with '#' is assumed, that these are
     * already valid ASN.1 objects encoded in hex.
     * <p>
     * All other string values are send to
     * {@link AbstractX500NameStyle#encodeStringValue(ASN1ObjectIdentifier, String)}.
     * </p>
     * Subclasses should overwrite
     * {@link AbstractX500NameStyle#encodeStringValue(ASN1ObjectIdentifier, String)}
     * to change the encoding of specific types.
     *
     * @param oid the DN name of the value.
     * @param value the String representation of the value.
     */
    public Asn1Encodable StringToValue(DerObjectIdentifier oid, string value)
    {
        if (value.Length != 0 && value[0] == '#')
        {
            try
            {
                return IetfUtils.ValueFromHexString(value, 1);
            }
            catch (IOException)
            {
                throw new Asn1ParsingException("can't recode value for oid " + oid.Id);
            }
        }

        if (value.Length != 0 && value[0] == '\\')
        {
            value = value.Substring(1);
        }

        return EncodeStringValue(oid, value);
    }

    /**
     * Encoded every value into a UTF8String.
     * <p>
     * Subclasses should overwrite
     * this method to change the encoding of specific types.
     * </p>
     *
     * @param oid the DN oid of the value
     * @param value the String representation of the value
     * @return a the value encoded into a ASN.1 object. Never returns <code>null</code>.
     */
    protected virtual Asn1Encodable EncodeStringValue(DerObjectIdentifier oid, String value)
    {
        return new DerUtf8String(value);
    }

    public virtual bool AreEqual(X500Name name1, X500Name name2)
    {
        Rdn[] rdns1 = name1.GetRdns();
        Rdn[] rdns2 = name2.GetRdns();

        if (rdns1.Length != rdns2.Length)
        {
            return false;
        }

        bool reverse = false;

        if (rdns1[0].First != null && rdns2[0].First != null)
        {
            reverse = !rdns1[0].First.Type.Equals(rdns2[0].First.Type);  // guess forward
        }

        for (int i = 0; i != rdns1.Length; i++)
        {
            if (!foundMatch(reverse, rdns1[i], rdns2))
            {
                return false;
            }
        }

        return true;
    }

    private bool foundMatch(bool reverse, Rdn rdn, Rdn[] possRDNs)
    {
        if (reverse)
        {
            for (int i = possRDNs.Length - 1; i >= 0; i--)
            {
                if (possRDNs[i] != null && RdnAreEqual(rdn, possRDNs[i]))
                {
                    possRDNs[i] = null;
                    return true;
                }
            }
        }
        else
        {
            for (int i = 0; i != possRDNs.Length; i++)
            {
                if (possRDNs[i] != null && RdnAreEqual(rdn, possRDNs[i]))
                {
                    possRDNs[i] = null;
                    return true;
                }
            }
        }

        return false;
    }

    protected bool RdnAreEqual(Rdn rdn1, Rdn rdn2)
    {
        return IetfUtils.RdnAreEqual(rdn1, rdn2);
    }

        public abstract DerObjectIdentifier AttrNameToOID(string attrName);
        public abstract Rdn[] FromString(string dirName);
        public abstract string ToString(X500Name name);
        public abstract string OidToDisplayName(DerObjectIdentifier oid);
        public abstract string[] OidToAttrNames(DerObjectIdentifier oid);
    }
}
