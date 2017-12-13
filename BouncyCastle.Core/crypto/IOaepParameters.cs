namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for OAEP parameters.
    /// </summary>
    /// <typeparam name="TParam">The type of the implementing parameter.</typeparam>
    /// <typeparam name="TAlg">The algorithm type for the parameters.</typeparam>
    /// <typeparam name="DAlg">The digest algorithm type for the parameters.</typeparam>
	public interface IOaepParameters<out TParam, out TAlg, DAlg>: IParameters<TAlg> where TAlg: Algorithm where DAlg: DigestAlgorithm
	{
        /// <summary>
        /// Return the digest algorithm associated with these parameters.
        /// </summary>
        DAlg DigestAlgorithm { get; }

        /// <summary>
        /// Return the digest algorithm used in the mask generation function associated with these parameters.
        /// </summary>
        DAlg MgfDigestAlgorithm { get; }
 
        /// <summary>
        /// Return the encoding parameters to be used in the padding created from these parameters.
        /// </summary>
        /// <returns>A copy of the encoding parameters.</returns>
        byte[] GetEncodingParams();

        /// <summary>
        ///  Create a new parameter instance with the OAEP encoding configured with the passed in digest.
        ///  Note: this will also set the MGF digest to the same algorithm.
        /// </summary>
        /// <param name="digestAlgorithm">The base digest function to use for the OAEP encoding.</param>
        /// <returns>A new instance of the parameter object configured for the new digest.</returns>
		TParam WithDigest (DAlg digestAlgorithm);

        /// <summary>
        /// Create a new parameter instance with the mask generation function configured with the passed in digest.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to use with the MGF.</param>
        /// <returns>A new instance of the parameter object configured for the new MGF digest.</returns>
		TParam WithMgfDigest (DAlg digestAlgorithm);

        /// <summary>
        /// Create a new parameter instance configured with the passed in salt.
        /// </summary>
        /// <param name="encodingParams">A specific encoding parameter to use with the OAEP encoding.</param>
        /// <returns>A new instance of the parameter object configured for the new encoding parameter.</returns>
		TParam WithEncodingParams (byte[] encodingParams);
	}
}

