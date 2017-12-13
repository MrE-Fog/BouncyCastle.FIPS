using System.IO;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Extension of cipher which provides for the processing of AAD in addition to the plain text/cipher text.
	/// </summary>
	public interface IAeadCipher: ICipher
	{
		/// <summary>
		/// Gets the stream for reading/writing data to be processed.
		/// </summary>
		/// <value>The stream associated representing the AAD for this cipher.</value>
		Stream AadStream { get; }

		/// <summary>
		/// Gets the size of the MAC.
		/// </summary>
		/// <value>The size of the MAC.</value>
		int MacSizeInBits { get; }

		/// <summary>
		/// Return the MAC calculated processing the data given to this cipher.
		/// </summary>
		/// <returns>The AEAD cipher's MAC.</returns>
		IBlockResult GetMac ();
	}
}

