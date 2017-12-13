namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Return type for operators that produce a block of data and an associated message digest.
    /// </summary>
	public interface IBlockResultWithDigest: IBlockResult
	{
        /// <summary>
        /// Return the digest associated with the final result of the operation. Note: this a reference, clearing it will
        /// have the same effect as clearing the object.
        /// </summary>
        /// <returns>A digest associated with the result of an operation.</returns>
        byte[] CollectDigest ();

        /// <summary>
        /// Store the digest associated with the final result of the operation by copying it into the destination array. Note:
        /// this has the effect of clearing the object.
        /// </summary>
        /// <returns>The number of bytes copied into destination.</returns>
        /// <param name="destination">The byte array to copy the digest into.</param>
        /// <param name="offset">The offset into destination to start copying the digest at.</param>
        int CollectDigest (byte[] destination, int offset);
	}
}
