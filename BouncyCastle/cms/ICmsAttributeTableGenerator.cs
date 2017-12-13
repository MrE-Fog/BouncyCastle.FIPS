using Org.BouncyCastle.Asn1.Cms;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    /// <remarks>
    /// The 'Signature' parameter is only available when generating unsigned attributes.
    /// </remarks>
    public class CmsAttributeTableParameter
    {
        public const string ContentType = "contentType";
        public const string Digest = "digest";
        public const string Signature = "encryptedDigest";
        public const string DigestAlgorithmIdentifier = "digestAlgID";
        public const string SignatureAlgorithmIdentifier = "signatureAlgID";
    }

    /// <summary>
    /// Base interface for a CMS Attribute table generator.
    /// </summary>
    public interface ICmsAttributeTableGenerator
    {
        /// <summary>
        /// Construct an AttributeTable from the passed in dictionary of (key, value) pairs.
        /// </summary>
        /// <param name="parameters">The (key, value) pairs to construct the returned table from.</param>
        /// <returns>A new attribute table.</returns>
        AttributeTable GetAttributes(IDictionary<string,object> parameters);
    }
}
