
namespace Org.BouncyCastle.Asn1.X500
{
    /// <summary>
    /// This interface provides a profile to conform to when
    /// DNs are being converted into strings and back. The idea being that we'll be able to deal with
    /// the number of standard ways the fields in a DN should be
    /// encoded into their ASN.1 counterparts - a number that is rapidly approaching the
    /// number of machines on the Internet.
    /// </summary>
    public interface IX500NameStyle
    {
        /// <summary>
        /// Convert the passed in String value into the appropriate ASN.1 encoded object.
        /// </summary>
        /// <param name="oid">The OID associated with the value in the DN.</param>
        /// <param name="value">The value of the particular DN component.</param>
        /// <returns>The ASN.1 equivalent for the value.</returns>
        Asn1Encodable StringToValue(DerObjectIdentifier oid, string value);

        /// <summary>
        /// Return the OID associated with the passed in name.
        /// </summary>
        /// <param name="attrName">The string to match.</param>
        /// <returns>An OID</returns>
        DerObjectIdentifier AttrNameToOID(string attrName);

        /// <summary>
        /// Return an array of RDN generated from the passed in String.
        /// </summary>
        /// <param name="dirName"> the String representation.</param>
        /// <returns>An array of corresponding RDNs.</returns>
        Rdn[] FromString(string dirName);

        /// <summary>
        /// Return true if the two names are equal.
        /// </summary>
        /// <param name="name1">First name for comparison.</param>
        /// <param name="name2">Second name for comparison.</param>
        /// <returns>true if name1 = name 2, false otherwise.</returns>
        bool AreEqual(X500Name name1, X500Name name2);

        /// <summary>
        /// Calculate a hashCode for the passed in name.
        /// </summary>
        /// <param name="name">The name the hashCode is required for.</param>
        /// <returns>The calculated hashCode.</returns>
        int CalculateHashCode(X500Name name);

        /// <summary>
        /// Convert the passed in X500Name to a String.
        /// </summary>
        /// <param name="name">The name to convert.</param>
        /// <returns>A String representation.</returns>
        string ToString(X500Name name);

        /// <summary>
        /// Return the display name for toString() associated with the OID.
        /// </summary>
        /// <param name="oid">The OID of interest.</param>
        /// <returns>The name displayed in toString(), null if no mapping provided.</returns>
        string OidToDisplayName(DerObjectIdentifier oid);

        /// <summary>
        /// Return the acceptable names in a String DN that map to OID.
        /// </summary>
        /// <param name="oid">The OID of interest.</param>
        /// <returns>An array of String aliases for the OID, zero length if there are none.</returns>
        string[] OidToAttrNames(DerObjectIdentifier oid);
    }
}
