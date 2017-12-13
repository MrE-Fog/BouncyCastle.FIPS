
namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Interface for a converter that produces a byte encoding for a char array.
	/// </summary>
	public interface ICharToByteConverter
	{
		/// <summary>
		/// Return the type of the conversion.
		/// </summary>
		/// <value>The type name for the conversion.</value>
		string Type { get; }

		/// <summary>
		/// Return a byte encoded representation of the passed in char array.
		/// </summary>
		/// <param name="str">The char array to convert</param>
		/// <returns>A byte encoding of str.</returns>
		byte[] Convert(char[] str);
	}
}

