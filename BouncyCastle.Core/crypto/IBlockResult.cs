
namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Operators that reduce their input to a single block return an object
	/// of this type.
	/// </summary>
	public interface IBlockResult
	{
		/// <summary>
		/// Return the number of bytes in the result
		/// </summary>
		/// <value>The length of the result in bytes.</value>
		int Length { get ; }

		/// <summary>
		/// Return the final result of the operation. Note: this a reference, clearing it will
		/// have the same effect as clearing the object.
		/// </summary>
		/// <returns>A block of bytes, representing the result of an operation.</returns>
		byte[] Collect();

		/// <summary>
		/// Store the final result of the operation by copying it into the destination array. Note:
		/// this has the effect of clearing the object.
		/// </summary>
		/// <returns>The number of bytes copied into destination.</returns>
		/// <param name="destination">The byte array to copy the result into.</param>
		/// <param name="offset">The offset into destination to start copying the result at.</param>
		int Collect(byte[] destination, int offset);
	}
}

