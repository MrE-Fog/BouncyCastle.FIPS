using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    public class BCStyle : AbstractX500NameStyle
    {
        /**
         * country code - StringType(SIZE(2))
         */
        public static readonly DerObjectIdentifier C = new DerObjectIdentifier("2.5.4.6").Intern();

        /**
         * organization - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier O = new DerObjectIdentifier("2.5.4.10").Intern();

        /**
         * organizational unit name - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier OU = new DerObjectIdentifier("2.5.4.11").Intern();

        /**
         * Title
         */
        public static readonly DerObjectIdentifier T = new DerObjectIdentifier("2.5.4.12").Intern();

        /**
         * common name - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier CN = new DerObjectIdentifier("2.5.4.3").Intern();

        /**
         * device serial number name - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier SN = new DerObjectIdentifier("2.5.4.5").Intern();

        /**
         * street - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier STREET = new DerObjectIdentifier("2.5.4.9").Intern();

        /**
         * device serial number name - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier SERIALNUMBER = SN;

        /**
         * locality name - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier L = new DerObjectIdentifier("2.5.4.7").Intern();

        /**
         * state, or province name - StringType(SIZE(1..64))
         */
        public static readonly DerObjectIdentifier ST = new DerObjectIdentifier("2.5.4.8").Intern();

        /**
         * Naming attributes of type X520name
         */
        public static readonly DerObjectIdentifier SURNAME = new DerObjectIdentifier("2.5.4.4").Intern();
        public static readonly DerObjectIdentifier GIVENNAME = new DerObjectIdentifier("2.5.4.42").Intern();
        public static readonly DerObjectIdentifier INITIALS = new DerObjectIdentifier("2.5.4.43").Intern();
        public static readonly DerObjectIdentifier GENERATION = new DerObjectIdentifier("2.5.4.44").Intern();
        public static readonly DerObjectIdentifier UNIQUE_IDENTIFIER = new DerObjectIdentifier("2.5.4.45").Intern();

        /**
         * businessCategory - DirectoryString(SIZE(1..128)
         */
        public static readonly DerObjectIdentifier BUSINESS_CATEGORY = new DerObjectIdentifier(
            "2.5.4.15").Intern();

        /**
         * postalCode - DirectoryString(SIZE(1..40)
         */
        public static readonly DerObjectIdentifier POSTAL_CODE = new DerObjectIdentifier(
            "2.5.4.17").Intern();

        /**
         * dnQualifier - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier DN_QUALIFIER = new DerObjectIdentifier(
            "2.5.4.46").Intern();

        /**
         * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier PSEUDONYM = new DerObjectIdentifier(
            "2.5.4.65").Intern();


        /**
         * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
         */
        public static readonly DerObjectIdentifier DATE_OF_BIRTH = new DerObjectIdentifier(
            "1.3.6.1.5.5.7.9.1").Intern();

        /**
         * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
         */
        public static readonly DerObjectIdentifier PLACE_OF_BIRTH = new DerObjectIdentifier(
            "1.3.6.1.5.5.7.9.2").Intern();

        /**
         * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
         */
        public static readonly DerObjectIdentifier GENDER = new DerObjectIdentifier(
            "1.3.6.1.5.5.7.9.3").Intern();

        /**
         * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        public static readonly DerObjectIdentifier COUNTRY_OF_CITIZENSHIP = new DerObjectIdentifier(
            "1.3.6.1.5.5.7.9.4").Intern();

        /**
         * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        public static readonly DerObjectIdentifier COUNTRY_OF_RESIDENCE = new DerObjectIdentifier(
            "1.3.6.1.5.5.7.9.5").Intern();


        /**
         * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier NAME_AT_BIRTH = new DerObjectIdentifier("1.3.36.8.3.14").Intern();

        /**
         * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
         * DirectoryString(SIZE(1..30))
         */
        public static readonly DerObjectIdentifier POSTAL_ADDRESS = new DerObjectIdentifier("2.5.4.16").Intern();

        /**
         * RFC 2256 dmdName
         */
        public static readonly DerObjectIdentifier DMD_NAME = new DerObjectIdentifier("2.5.4.54").Intern();

        /**
         * id-at-telephoneNumber
         */
        public static readonly DerObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;

        /**
         * id-at-name
         */
        public static readonly DerObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;

        /**
         * Email address (RSA PKCS#9 extension) - IA5String.
         * <p/>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
         */
        public static readonly DerObjectIdentifier EmailAddress = PkcsObjectIdentifiers.Pkcs9AtEmailAddress;

        /**
         * more from PKCS#9
         */
        public static readonly DerObjectIdentifier UnstructuredName = PkcsObjectIdentifiers.Pkcs9AtUnstructuredName;
        public static readonly DerObjectIdentifier UnstructuredAddress = PkcsObjectIdentifiers.Pkcs9AtUnstructuredAddress;

        /**
         * email address in Verisign certificates
         */
        public static readonly DerObjectIdentifier E = EmailAddress;

        /*
        * others...
        */
        public static readonly DerObjectIdentifier DC = new DerObjectIdentifier("0.9.2342.19200300.100.1.25");

        /**
         * LDAP User id.
         */
        public static readonly DerObjectIdentifier UID = new DerObjectIdentifier("0.9.2342.19200300.100.1.1");

        /**
         * default look up table translating OID values into their common symbols following
         * the convention in RFC 2253 with a few extras
         */
        private static readonly IDictionary DefaultSymbols = Platform.CreateHashtable();

        /**
         * look up table translating common symbols into their OIDS.
         */
        private static readonly IDictionary DefaultLookUp = Platform.CreateHashtable();

        /// <remarks>
        /// Singleton instance.
        /// </remarks>
        public static readonly IX500NameStyle Instance;

        static BCStyle()
        {
            DefaultSymbols.Add(C, "C");
            DefaultSymbols.Add(O, "O");
            DefaultSymbols.Add(T, "T");
            DefaultSymbols.Add(OU, "OU");
            DefaultSymbols.Add(CN, "CN");
            DefaultSymbols.Add(L, "L");
            DefaultSymbols.Add(ST, "ST");
            DefaultSymbols.Add(SN, "SERIALNUMBER");
            DefaultSymbols.Add(EmailAddress, "E");
            DefaultSymbols.Add(DC, "DC");
            DefaultSymbols.Add(UID, "UID");
            DefaultSymbols.Add(STREET, "STREET");
            DefaultSymbols.Add(SURNAME, "SURNAME");
            DefaultSymbols.Add(GIVENNAME, "GIVENNAME");
            DefaultSymbols.Add(INITIALS, "INITIALS");
            DefaultSymbols.Add(GENERATION, "GENERATION");
            DefaultSymbols.Add(UnstructuredAddress, "unstructuredAddress");
            DefaultSymbols.Add(UnstructuredName, "unstructuredName");
            DefaultSymbols.Add(UNIQUE_IDENTIFIER, "UniqueIdentifier");
            DefaultSymbols.Add(DN_QUALIFIER, "DN");
            DefaultSymbols.Add(PSEUDONYM, "Pseudonym");
            DefaultSymbols.Add(POSTAL_ADDRESS, "PostalAddress");
            DefaultSymbols.Add(NAME_AT_BIRTH, "NameAtBirth");
            DefaultSymbols.Add(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
            DefaultSymbols.Add(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
            DefaultSymbols.Add(GENDER, "Gender");
            DefaultSymbols.Add(PLACE_OF_BIRTH, "PlaceOfBirth");
            DefaultSymbols.Add(DATE_OF_BIRTH, "DateOfBirth");
            DefaultSymbols.Add(POSTAL_CODE, "PostalCode");
            DefaultSymbols.Add(BUSINESS_CATEGORY, "BusinessCategory");
            DefaultSymbols.Add(TELEPHONE_NUMBER, "TelephoneNumber");
            DefaultSymbols.Add(NAME, "Name");

            DefaultLookUp.Add("c", C);
            DefaultLookUp.Add("o", O);
            DefaultLookUp.Add("t", T);
            DefaultLookUp.Add("ou", OU);
            DefaultLookUp.Add("cn", CN);
            DefaultLookUp.Add("l", L);
            DefaultLookUp.Add("st", ST);
            DefaultLookUp.Add("sn", SN);
            DefaultLookUp.Add("serialnumber", SN);
            DefaultLookUp.Add("street", STREET);
            DefaultLookUp.Add("emailaddress", E);
            DefaultLookUp.Add("dc", DC);
            DefaultLookUp.Add("e", E);
            DefaultLookUp.Add("uid", UID);
            DefaultLookUp.Add("surname", SURNAME);
            DefaultLookUp.Add("givenname", GIVENNAME);
            DefaultLookUp.Add("initials", INITIALS);
            DefaultLookUp.Add("generation", GENERATION);
            DefaultLookUp.Add("unstructuredaddress", UnstructuredAddress);
            DefaultLookUp.Add("unstructuredname", UnstructuredName);
            DefaultLookUp.Add("uniqueidentifier", UNIQUE_IDENTIFIER);
            DefaultLookUp.Add("dn", DN_QUALIFIER);
            DefaultLookUp.Add("pseudonym", PSEUDONYM);
            DefaultLookUp.Add("postaladdress", POSTAL_ADDRESS);
            DefaultLookUp.Add("nameofbirth", NAME_AT_BIRTH);
            DefaultLookUp.Add("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
            DefaultLookUp.Add("countryofresidence", COUNTRY_OF_RESIDENCE);
            DefaultLookUp.Add("gender", GENDER);
            DefaultLookUp.Add("placeofbirth", PLACE_OF_BIRTH);
            DefaultLookUp.Add("dateofbirth", DATE_OF_BIRTH);
            DefaultLookUp.Add("postalcode", POSTAL_CODE);
            DefaultLookUp.Add("businesscategory", BUSINESS_CATEGORY);
            DefaultLookUp.Add("telephonenumber", TELEPHONE_NUMBER);
            DefaultLookUp.Add("name", NAME);

            Instance = new BCStyle();
        }

        protected readonly IDictionary mDefaultLookUp;
        protected readonly IDictionary mDefaultSymbols;

        protected BCStyle()
        {
            mDefaultSymbols = CopyHashTable(DefaultSymbols);
            mDefaultLookUp = CopyHashTable(DefaultLookUp);
        }

        protected override Asn1Encodable EncodeStringValue(DerObjectIdentifier oid,
                String value)
        {
            if (oid.Equals(EmailAddress) || oid.Equals(DC))
            {
                return new DerIA5String(value);
            }
            else if (oid.Equals(DATE_OF_BIRTH))  // accept time string as well as # (for compatibility)
            {
                return new DerGeneralizedTime(value);
            }
            else if (oid.Equals(C) || oid.Equals(SN) || oid.Equals(DN_QUALIFIER)
                || oid.Equals(TELEPHONE_NUMBER))
            {
                return new DerPrintableString(value);
            }

            return base.EncodeStringValue(oid, value);
        }

        public override string OidToDisplayName(DerObjectIdentifier oid)
        {
            return (string)DefaultSymbols[oid];
        }

        public override string[] OidToAttrNames(DerObjectIdentifier oid)
        {
            return IetfUtils.FindAttrNamesForOID(oid, mDefaultLookUp);
        }

        public override DerObjectIdentifier AttrNameToOID(string attrName)
        {
            return IetfUtils.DecodeAttrName(attrName, mDefaultLookUp);
        }

        public override Rdn[] FromString(string dirName)
        {
            return IetfUtils.rDNsFromString(dirName, this);
        }

        public override string ToString(X500Name name)
        {
            StringBuilder buf = new StringBuilder();
            bool first = true;

            Rdn[] rdns = name.GetRdns();

            for (int i = 0; i < rdns.Length; i++)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    buf.Append(',');
                }

                IetfUtils.AppendRdn(buf, rdns[i], mDefaultSymbols);
            }

            return buf.ToString();
        }
    }
}
