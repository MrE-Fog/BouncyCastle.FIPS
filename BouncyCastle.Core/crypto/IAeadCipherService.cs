
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for AEAD ciphers.
    /// </summary>
    public interface IAeadCipherService
    {
        /// <summary>
        /// Return an AEAD cipher builder which will build decrypting ciphers.
        /// </summary>
        /// <typeparam name="A">The type of the details for AEAD cipher to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of AEAD cipher to be produced.</param>
        /// <returns></returns>
        IAeadCipherBuilder<A> CreateAeadDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;

        /// <summary>
        /// Return an AEAD cipher builder which will build encrypting ciphers.
        /// </summary>
        /// <typeparam name="A">The type of the details for AEAD cipher to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of AEAD cipher to be produced.</param>
        /// <returns></returns>
        IAeadCipherBuilder<A> CreateAeadEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
