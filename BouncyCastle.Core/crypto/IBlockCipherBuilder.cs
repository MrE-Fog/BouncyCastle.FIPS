
using System.IO;

using Org.BouncyCastle.Crypto.Paddings;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for block cipher builders.
    /// </summary>
    /// <typeparam name="A">algorithm details type parameter.</typeparam>
    public interface IBlockCipherBuilder<out A>
	{
        /// <summary>
        /// Return the algorithm and parameter details associated with any block cipher built.
        /// </summary>
        A AlgorithmDetails { get ; }

        /// <summary>
        /// Return the blocksize for the underlying block cipher.
        /// </summary>
		int BlockSize { get; }

        /// <summary>
        /// Return the maximum output size that a given input will produce.
        /// </summary>
        /// <param name="inputLen">the length of the expected input.</param>
        /// <returns>The maximum possible output size that can produced for the expected input length.</returns>
        int GetMaxOutputSize (int inputLen);

        /// <summary>
        /// Build a cipher that operates on the passed in stream and uses the passed in padding.
        /// </summary>
        /// <param name="stream">The stream to write/read any encrypted/decrypted data.</param>
        /// <param name="padding">The padding to use with the data processed.</param>
        /// <returns>A cipher based around the given stream and padding</returns>
		ICipher BuildPaddedCipher(Stream stream, IBlockCipherPadding padding);

        /// <summary>
        /// Build a block cipher that operates on the passed in stream.
        /// </summary>
        /// <param name="stream">The stream to write/read any encrypted/decrypted data.</param>
        /// <returns>A cipher based around the given stream.</returns>
		IBlockCipher BuildBlockCipher(Stream stream);
	}
}

