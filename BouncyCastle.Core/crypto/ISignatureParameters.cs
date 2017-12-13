namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for signature parameters.
    /// </summary>
    /// <typeparam name="TParam">The type of the implementing parameter.</typeparam>
    /// <typeparam name="TAlg">The algorithm type for the parameters.</typeparam>
    /// <typeparam name="DAlg">The digest algorithm type for the parameters.</typeparam>
	public interface ISignatureParameters<out TParam, out TAlg, DAlg> where TAlg: Algorithm where DAlg: DigestAlgorithm
	{
        /// <summary>
        /// Return the digest algorithm for processing the message to be signed.
        /// </summary>
        DAlg DigestAlgorithm { get; }

        /// <summary>
        /// Set the digest algorithm.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to use.</param>
        /// <returns>A new parameter set with the changed configuration.</returns>
        TParam WithDigest (DAlg digestAlgorithm);
	}
}

