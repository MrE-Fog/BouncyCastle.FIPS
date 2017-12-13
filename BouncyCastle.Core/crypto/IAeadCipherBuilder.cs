using System.IO;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for AEAD cipher builders.
    /// </summary>
    /// <typeparam name="A">algorithm details type parameter.</typeparam>
	public interface IAeadCipherBuilder<out A>: ICipherBuilder<A>
	{
        /// <summary>
        /// Build a cipher for the algorithm and parameter details in this builder.
        /// </summary>
        /// <param name="usage">The manner in which associated data will be introduced.</param>
        /// <param name="stream">The stream to write/read any encrypted/decrypted data.</param>
        /// <returns></returns>
		IAeadCipher BuildAeadCipher(AeadUsage usage, Stream stream);
	}
}

