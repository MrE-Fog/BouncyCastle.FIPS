namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for a provider of AEAD decryptor builders.
    /// </summary>
    /// <typeparam name="A">The algorithm/parameter details type the builders are for.</typeparam>
    public interface IAeadDecryptorBuilderProvider<A>
    {
        /// <summary>
        /// Create an AEAD decryptor builder for the given details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm/parameter details type the builder is for.</param>
        /// <returns>An AEAD cipher builder which produces decryptors for the given details.</returns>
        IAeadCipherBuilder<A> CreateAeadDecryptorBuilder(A algorithmDetails);
    }
}
