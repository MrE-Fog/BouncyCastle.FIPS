using System;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Base interface for keys.
	/// </summary>
	public interface IKey
	{
		/// <summary>
		/// Gets the algorithm the key is for.
		/// </summary>
		/// <returns>The key's algorithm.</returns>
		Algorithm Algorithm { get; }

		/// <summary>
		/// Determines whether the specified <see cref="System.Object"/> is equal to the current <see cref="Org.BouncyCastle.Crypto.IKey"/>.
		/// </summary>
		/// <param name="o">The <see cref="System.Object"/> to compare with the current <see cref="Org.BouncyCastle.Crypto.IKey"/>.</param>
		/// <returns><c>true</c> if the specified <see cref="System.Object"/> is equal to the current
		/// <see cref="Org.BouncyCastle.Crypto.IKey"/>; otherwise, <c>false</c>.</returns>
		bool Equals(object o);

		/// <summary>
		/// Return the hash code for the key.
		/// </summary>
		/// <returns>A hash code for this instance that is suitable for use in hashing algorithms and data structures such as a hash table.</returns>
		int GetHashCode();
	}
}

