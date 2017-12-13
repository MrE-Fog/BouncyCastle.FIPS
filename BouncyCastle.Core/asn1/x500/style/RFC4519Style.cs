using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Asn1.X500.Style
{
    public class Rfc4519Style : AbstractX500NameStyle
    {
        public static readonly DerObjectIdentifier businessCategory = new DerObjectIdentifier("2.5.4.15").Intern();
        public static readonly DerObjectIdentifier c = new DerObjectIdentifier("2.5.4.6").Intern();
        public static readonly DerObjectIdentifier cn = new DerObjectIdentifier("2.5.4.3").Intern();
        public static readonly DerObjectIdentifier dc = new DerObjectIdentifier("0.9.2342.19200300.100.1.25").Intern();
        public static readonly DerObjectIdentifier description = new DerObjectIdentifier("2.5.4.13").Intern();
        public static readonly DerObjectIdentifier destinationIndicator = new DerObjectIdentifier("2.5.4.27").Intern();
        public static readonly DerObjectIdentifier distinguishedName = new DerObjectIdentifier("2.5.4.49").Intern();
        public static readonly DerObjectIdentifier dnQualifier = new DerObjectIdentifier("2.5.4.46").Intern();
        public static readonly DerObjectIdentifier enhancedSearchGuide = new DerObjectIdentifier("2.5.4.47").Intern();
        public static readonly DerObjectIdentifier facsimileTelephoneNumber = new DerObjectIdentifier("2.5.4.23").Intern();
        public static readonly DerObjectIdentifier generationQualifier = new DerObjectIdentifier("2.5.4.44").Intern();
        public static readonly DerObjectIdentifier givenName = new DerObjectIdentifier("2.5.4.42").Intern();
        public static readonly DerObjectIdentifier houseIdentifier = new DerObjectIdentifier("2.5.4.51").Intern();
        public static readonly DerObjectIdentifier initials = new DerObjectIdentifier("2.5.4.43").Intern();
        public static readonly DerObjectIdentifier internationalISDNNumber = new DerObjectIdentifier("2.5.4.25").Intern();
        public static readonly DerObjectIdentifier l = new DerObjectIdentifier("2.5.4.7").Intern();
        public static readonly DerObjectIdentifier member = new DerObjectIdentifier("2.5.4.31").Intern();
        public static readonly DerObjectIdentifier name = new DerObjectIdentifier("2.5.4.41").Intern();
        public static readonly DerObjectIdentifier o = new DerObjectIdentifier("2.5.4.10").Intern();
        public static readonly DerObjectIdentifier ou = new DerObjectIdentifier("2.5.4.11").Intern();
        public static readonly DerObjectIdentifier owner = new DerObjectIdentifier("2.5.4.32").Intern();
        public static readonly DerObjectIdentifier physicalDeliveryOfficeName = new DerObjectIdentifier("2.5.4.19").Intern();
        public static readonly DerObjectIdentifier postalAddress = new DerObjectIdentifier("2.5.4.16").Intern();
        public static readonly DerObjectIdentifier postalCode = new DerObjectIdentifier("2.5.4.17").Intern();
        public static readonly DerObjectIdentifier postOfficeBox = new DerObjectIdentifier("2.5.4.18").Intern();
        public static readonly DerObjectIdentifier preferredDeliveryMethod = new DerObjectIdentifier("2.5.4.28").Intern();
        public static readonly DerObjectIdentifier registeredAddress = new DerObjectIdentifier("2.5.4.26").Intern();
        public static readonly DerObjectIdentifier roleOccupant = new DerObjectIdentifier("2.5.4.33").Intern();
        public static readonly DerObjectIdentifier searchGuide = new DerObjectIdentifier("2.5.4.14").Intern();
        public static readonly DerObjectIdentifier seeAlso = new DerObjectIdentifier("2.5.4.34").Intern();
        public static readonly DerObjectIdentifier serialNumber = new DerObjectIdentifier("2.5.4.5").Intern();
        public static readonly DerObjectIdentifier sn = new DerObjectIdentifier("2.5.4.4").Intern();
        public static readonly DerObjectIdentifier st = new DerObjectIdentifier("2.5.4.8").Intern();
        public static readonly DerObjectIdentifier street = new DerObjectIdentifier("2.5.4.9").Intern();
        public static readonly DerObjectIdentifier telephoneNumber = new DerObjectIdentifier("2.5.4.20").Intern();
        public static readonly DerObjectIdentifier teletexTerminalIdentifier = new DerObjectIdentifier("2.5.4.22").Intern();
        public static readonly DerObjectIdentifier telexNumber = new DerObjectIdentifier("2.5.4.21").Intern();
        public static readonly DerObjectIdentifier title = new DerObjectIdentifier("2.5.4.12").Intern();
        public static readonly DerObjectIdentifier uid = new DerObjectIdentifier("0.9.2342.19200300.100.1.1").Intern();
        public static readonly DerObjectIdentifier uniqueMember = new DerObjectIdentifier("2.5.4.50").Intern();
        public static readonly DerObjectIdentifier userPassword = new DerObjectIdentifier("2.5.4.35").Intern();
        public static readonly DerObjectIdentifier x121Address = new DerObjectIdentifier("2.5.4.24").Intern();
        public static readonly DerObjectIdentifier x500UniqueIdentifier = new DerObjectIdentifier("2.5.4.45").Intern();

        /**
         * default look up table translating OID values into their common symbols following
         * the convention in RFC 2253 with a few extras
         */
        private static readonly IDictionary DefaultSymbols = Platform.CreateHashtable();

        /**
         * look up table translating common symbols into their OIDS.
         */
        private static readonly IDictionary DefaultLookUp = Platform.CreateHashtable();

        static Rfc4519Style()
        {
            DefaultSymbols.Add(businessCategory, "businessCategory");
            DefaultSymbols.Add(c, "c");
            DefaultSymbols.Add(cn, "cn");
            DefaultSymbols.Add(dc, "dc");
            DefaultSymbols.Add(description, "description");
            DefaultSymbols.Add(destinationIndicator, "destinationIndicator");
            DefaultSymbols.Add(distinguishedName, "distinguishedName");
            DefaultSymbols.Add(dnQualifier, "dnQualifier");
            DefaultSymbols.Add(enhancedSearchGuide, "enhancedSearchGuide");
            DefaultSymbols.Add(facsimileTelephoneNumber, "facsimileTelephoneNumber");
            DefaultSymbols.Add(generationQualifier, "generationQualifier");
            DefaultSymbols.Add(givenName, "givenName");
            DefaultSymbols.Add(houseIdentifier, "houseIdentifier");
            DefaultSymbols.Add(initials, "initials");
            DefaultSymbols.Add(internationalISDNNumber, "internationalISDNNumber");
            DefaultSymbols.Add(l, "l");
            DefaultSymbols.Add(member, "member");
            DefaultSymbols.Add(name, "name");
            DefaultSymbols.Add(o, "o");
            DefaultSymbols.Add(ou, "ou");
            DefaultSymbols.Add(owner, "owner");
            DefaultSymbols.Add(physicalDeliveryOfficeName, "physicalDeliveryOfficeName");
            DefaultSymbols.Add(postalAddress, "postalAddress");
            DefaultSymbols.Add(postalCode, "postalCode");
            DefaultSymbols.Add(postOfficeBox, "postOfficeBox");
            DefaultSymbols.Add(preferredDeliveryMethod, "preferredDeliveryMethod");
            DefaultSymbols.Add(registeredAddress, "registeredAddress");
            DefaultSymbols.Add(roleOccupant, "roleOccupant");
            DefaultSymbols.Add(searchGuide, "searchGuide");
            DefaultSymbols.Add(seeAlso, "seeAlso");
            DefaultSymbols.Add(serialNumber, "serialNumber");
            DefaultSymbols.Add(sn, "sn");
            DefaultSymbols.Add(st, "st");
            DefaultSymbols.Add(street, "street");
            DefaultSymbols.Add(telephoneNumber, "telephoneNumber");
            DefaultSymbols.Add(teletexTerminalIdentifier, "teletexTerminalIdentifier");
            DefaultSymbols.Add(telexNumber, "telexNumber");
            DefaultSymbols.Add(title, "title");
            DefaultSymbols.Add(uid, "uid");
            DefaultSymbols.Add(uniqueMember, "uniqueMember");
            DefaultSymbols.Add(userPassword, "userPassword");
            DefaultSymbols.Add(x121Address, "x121Address");
            DefaultSymbols.Add(x500UniqueIdentifier, "x500UniqueIdentifier");

            DefaultLookUp.Add("businesscategory", businessCategory);
            DefaultLookUp.Add("c", c);
            DefaultLookUp.Add("cn", cn);
            DefaultLookUp.Add("dc", dc);
            DefaultLookUp.Add("description", description);
            DefaultLookUp.Add("destinationindicator", destinationIndicator);
            DefaultLookUp.Add("distinguishedname", distinguishedName);
            DefaultLookUp.Add("dnqualifier", dnQualifier);
            DefaultLookUp.Add("enhancedsearchguide", enhancedSearchGuide);
            DefaultLookUp.Add("facsimiletelephonenumber", facsimileTelephoneNumber);
            DefaultLookUp.Add("generationqualifier", generationQualifier);
            DefaultLookUp.Add("givenname", givenName);
            DefaultLookUp.Add("houseidentifier", houseIdentifier);
            DefaultLookUp.Add("initials", initials);
            DefaultLookUp.Add("internationalisdnnumber", internationalISDNNumber);
            DefaultLookUp.Add("l", l);
            DefaultLookUp.Add("member", member);
            DefaultLookUp.Add("name", name);
            DefaultLookUp.Add("o", o);
            DefaultLookUp.Add("ou", ou);
            DefaultLookUp.Add("owner", owner);
            DefaultLookUp.Add("physicaldeliveryofficename", physicalDeliveryOfficeName);
            DefaultLookUp.Add("postaladdress", postalAddress);
            DefaultLookUp.Add("postalcode", postalCode);
            DefaultLookUp.Add("postofficebox", postOfficeBox);
            DefaultLookUp.Add("preferreddeliverymethod", preferredDeliveryMethod);
            DefaultLookUp.Add("registeredaddress", registeredAddress);
            DefaultLookUp.Add("roleoccupant", roleOccupant);
            DefaultLookUp.Add("searchguide", searchGuide);
            DefaultLookUp.Add("seealso", seeAlso);
            DefaultLookUp.Add("serialnumber", serialNumber);
            DefaultLookUp.Add("sn", sn);
            DefaultLookUp.Add("st", st);
            DefaultLookUp.Add("street", street);
            DefaultLookUp.Add("telephonenumber", telephoneNumber);
            DefaultLookUp.Add("teletexterminalidentifier", teletexTerminalIdentifier);
            DefaultLookUp.Add("telexnumber", telexNumber);
            DefaultLookUp.Add("title", title);
            DefaultLookUp.Add("uid", uid);
            DefaultLookUp.Add("uniquemember", uniqueMember);
            DefaultLookUp.Add("userpassword", userPassword);
            DefaultLookUp.Add("x121address", x121Address);
            DefaultLookUp.Add("x500uniqueidentifier", x500UniqueIdentifier);

            // TODO: need to add correct matching for equality comparisons.
        }

        /**
         * Singleton instance.
         */
        public static readonly IX500NameStyle INSTANCE = new Rfc4519Style();

        protected readonly IDictionary defaultLookUp;
        protected readonly IDictionary defaultSymbols;

        protected Rfc4519Style()
        {
            defaultSymbols = CopyHashTable(DefaultSymbols);
            defaultLookUp = CopyHashTable(DefaultLookUp);
        }

        protected override Asn1Encodable EncodeStringValue(DerObjectIdentifier oid,
                string value)
        {
            if (oid.Equals(dc))
            {
                return new DerIA5String(value);
            }
            else if (oid.Equals(c) || oid.Equals(serialNumber) || oid.Equals(dnQualifier)
                || oid.Equals(telephoneNumber))
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
            return IetfUtils.FindAttrNamesForOID(oid, defaultLookUp);
        }

        public override DerObjectIdentifier AttrNameToOID(String attrName)
        {
            return IetfUtils.DecodeAttrName(attrName, defaultLookUp);
        }

        // parse backwards
        public override Rdn[] FromString(string dirName)
        {
            Rdn[] tmp = IetfUtils.rDNsFromString(dirName, this);
            Rdn[] res = new Rdn[tmp.Length];

            for (int i = 0; i != tmp.Length; i++)
            {
                res[res.Length - i - 1] = tmp[i];
            }

            return res;
        }

        // convert in reverse
        public override string ToString(X500Name name)
        {
            StringBuilder buf = new StringBuilder();
            bool first = true;

            Rdn[] rdns = name.GetRdns();

            for (int i = rdns.Length - 1; i >= 0; i--)
            {
                if (first)
                {
                    first = false;
                }
                else
                {
                    buf.Append(',');
                }

                IetfUtils.AppendRdn(buf, rdns[i], defaultSymbols);
            }

            return buf.ToString();
        }
    }
}
