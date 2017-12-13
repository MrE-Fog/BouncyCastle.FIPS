using System.IO;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Base interface for a cipher that requires block aligned input.
	/// </summary>
	public interface IBlockCipher
	{
		/// <summary>
		/// The block size for this cipher.
		/// </summary>
		/// <value>The size of the block.</value>
		int BlockSize { get; }

		/// <summary>
		/// Return the size of the output buffer required for a Write() plus a
		/// close() with the write() being passed inputLen bytes.
		/// <para>
		/// The returned size may be dependent on the initialisation of this cipher
		/// and may not be accurate once subsequent input data is processed as the cipher may
		/// add, add or remove padding, as it sees fit.
		/// </para>
		/// </summary>
		/// <returns>The space required to accommodate a call to processBytes and doFinal with inputLen bytes of input.</returns>
		/// <param name="inputLen">The length of the expected input.</param>
		int GetMaxOutputSize (int inputLen);

		/// <summary>
		/// Return the size of the output buffer required for a write() with the write() being
		/// passed inputLen bytes and just updating the cipher output.
		/// </summary>
		/// <returns>The space required to accommodate a call to processBytes with inputLen bytes of input.</returns>
		/// <param name="inputLen">The length of the expected input.</param>
		int GetUpdateOutputSize(int inputLen);

		/// <summary>
		/// Gets the stream for reading/writing data processed/to be processed.
		/// </summary>
		/// <value>The stream associated with this block cipher.</value>
		Stream Stream { get; }
	}
}

