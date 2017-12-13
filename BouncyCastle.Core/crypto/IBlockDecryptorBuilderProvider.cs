
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for a provider of block cipher decryptor builders.
    /// </summary>
    /// <typeparam name="A">The algorithm/parameter details type the builders are for.</typeparam>
	public interface IBlockDecryptorBuilderProvider<A>
	{
        /// <summary>
        /// Create a block decryptor builder for the given details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm/parameter details type the builder is for.</param>
        /// <returns>A block cipher builder which produces decryptors for the given details.</returns>
        IBlockCipherBuilder<A> CreateBlockDecryptorBuilder(A algorithmDetails);
	}
}

