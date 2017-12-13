namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for a provider of AEAD encryptor builders.
    /// </summary>
    /// <typeparam name="A">The algorithm/parameter details type the builders are for.</typeparam>
    internal interface IAeadEncryptorBuilderProvider<A>
    {
        /// <summary>
        /// Create an AEAD encryptor builder for the given details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm/parameter details type the builder is for.</param>
        /// <returns>An AEAD cipher builder which produces encryptors for the given details.</returns>
        IAeadCipherBuilder<A> CreateAeadEncryptorBuilder(A algorithmDetails);
    }
}
