
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for a provider of block cipher encryptor builders.
    /// </summary>
    /// <typeparam name="A">The algorithm/parameter details type the builders are for.</typeparam>
    internal interface IBlockEncryptorBuilderProvider<A>
    {
        /// <summary>
        /// Create a block encryptor builder for the given details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm/parameter details type the builder is for.</param>
        /// <returns>A block cipher builder which produces encryptors for the given details.</returns>
        IBlockCipherBuilder<A> CreateBlockEncryptorBuilder(A algorithmDetails);
    }
}
