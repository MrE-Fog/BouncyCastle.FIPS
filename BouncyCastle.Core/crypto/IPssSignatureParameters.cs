namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for PSS signature parameters.
    /// </summary>
    /// <typeparam name="TParam">The type of the implementing parameter.</typeparam>
    /// <typeparam name="TAlg">The algorithm type for the parameters.</typeparam>
    /// <typeparam name="DAlg">The digest algorithm type for the parameters.</typeparam>
	public interface IPssSignatureParameters<out TParam, out TAlg, DAlg> where TAlg: Algorithm where DAlg: DigestAlgorithm
	{
        /// <summary>
        /// Return the digest algorithm for processing the message to be signed.
        /// </summary>
        DAlg DigestAlgorithm { get; }

        /// <summary>
        /// Return the digest algorithm to be used in the mask generation function.
        /// </summary>
        DAlg MgfDigestAlgorithm { get; }

        /// <summary>
        /// Return the length of the salt specified for these parameters.
        /// </summary>
        int SaltLength { get; }

        /// <summary>
        /// Return the fixed salt the parameters are configured with, if present.
        /// </summary>
        /// <returns>The fixed salt if available, null otherwise.</returns>
        byte[] GetSalt();

        /// <summary>
        /// Set the digest algorithm. Note: this will also set the MGF digest to the same algorithm.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to use.</param>
        /// <returns>A new parameter set with the changed configuration.</returns>
        TParam WithDigest(DAlg digestAlgorithm);

        /// <summary>
        /// Create a new parameter instance with the mask generation function configured with the passed in digest.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to use with the MGF.</param>
        /// <returns>A new instance of the parameter object configured for the new MGF digest.</returns>
        TParam WithMgfDigest (DAlg digestAlgorithm);

        /// <summary>
        /// Create a new parameter instance with a static salt configured for signatures generated.
        /// </summary>
        /// <param name="salt"></param>
        /// <returns>A new instance of the parameter object configured for the new salt.</returns>
		TParam WithSalt (byte[] salt);

        /// <summary>
        /// Create a new parameter instance with a specific salt length configured for signatures generated.
        /// </summary>
        /// <param name="saltLength">The length of the salt to use, or assume.</param>
        /// <returns>A new instance of the parameter object configured for the new salt length.</returns>
		TParam WithSaltLength (int saltLength);
	}
}

