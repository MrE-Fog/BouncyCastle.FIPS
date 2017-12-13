namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface describing a provider of cipher builders for creating decrypting ciphers.
    /// </summary>
    /// <typeparam name="A">The algorithm details/parameter type for the cipher builders produced.</typeparam>
    public interface IDecryptorBuilderProvider<A>
	{
        /// <summary>
        /// Return a cipher builder for creating decrypting ciphers.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm details/parameters to use to create the final cipher.</param>
        /// <returns>A new cipher builder.</returns>
        ICipherBuilder<A> CreateDecryptorBuilder (A algorithmDetails);
    }
}

