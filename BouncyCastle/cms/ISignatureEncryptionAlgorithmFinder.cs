using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Finder which is used to look up the algorithm identifiers representing the encryption algorithms that
    /// are associated with a particular signature algorithm.
    /// </summary>
    public interface ISignatureEncryptionAlgorithmFinder
    {
        /// <summary>
        /// Return the encryption algorithm identifier associated with the passed in signatureAlgorithm
        /// </summary>
        /// <param name="signatureAlgorithm">the algorithm identifier of the signature of interest</param>
        /// <returns>the algorithm identifier to be associated with the encryption algorithm used in signature creation.</returns>
        AlgorithmIdentifier FindEncryptionAlgorithm(AlgorithmIdentifier signatureAlgorithm);
    }
}
