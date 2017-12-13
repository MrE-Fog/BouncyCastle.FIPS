using Org.BouncyCastle.Asn1.X509;
using System;

namespace Org.BouncyCastle.Operators.Utilities
{ 
    /// <summary>
    /// Base interface for a finder of digests algorithm identifiers used with signatures.
    /// </summary>
    public interface IDigestAlgorithmIdentifierFinder
    {
        /// <summary>
        /// Find the digest algorithm identifier that matches with the passed in signature algorithm identifier.
        /// </summary>
        /// <param name="sigAlgId">the signature algorithm of interest.</param>
        /// <returns>an algorithm identifier for the corresponding digest.</returns>
        AlgorithmIdentifier Find(AlgorithmIdentifier sigAlgId);

        /// <summary>
        /// Find the algorithm identifier that matches with the passed in digest name.
        /// </summary>
        /// <param name="digAlgName">the name of the digest algorithm of interest.</param>
        /// <returns>an algorithm identifier for the digest signature.</returns>
        AlgorithmIdentifier Find(String digAlgName);
    }
}
