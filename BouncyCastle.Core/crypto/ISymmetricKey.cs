using System;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Interface describing a symmetric key.
	/// </summary>
	public interface ISymmetricKey: IKey
	{
        /// <summary>
        /// Return the bytes associated with this key.
        /// </summary>
        /// <returns>Key bytes, null or exception if they are not available.</returns>
        byte[] GetKeyBytes();
	}
}

