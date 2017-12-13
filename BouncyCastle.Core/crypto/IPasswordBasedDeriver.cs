using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for password based key derivers.
    /// </summary>
    /// <typeparam name="A">Type for the deriver's configuration parameters.</typeparam>
	public interface IPasswordBasedDeriver<out A>
	{
		/// <summary>
		/// Return the parameters for this deriver.
		/// </summary>
		/// <returns>the deriver's parameters.</returns>
		A AlgorithmDetails { get ; }

		/// <summary>
		/// Derive a key of the given keySizeInBytes length.
		/// </summary>
		/// <returns>A byte array containing the raw key data.</returns>
		/// <param name="keyType">Type of key to be calculated.</param>
		/// <param name="keySizeInBytes">The number of bytes to be produced.</param>
	    byte[] DeriveKey(TargetKeyType keyType, int keySizeInBytes);

		/// <summary>
		/// Derive a key of the given keySizeInBytes length and an iv of ivSizeInBytes length.
		/// </summary>
		/// <returns>a 2 element byte[] array containing the raw key data in element 0, the iv in element 1.</returns>
		/// <param name="keyType">Type of key to be calculated.</param>
		/// <param name="keySizeInBytes">The number of bytes to be produced for the key data.</param>
		/// <param name="ivSizeInBytes">The number of bytes to be produced for the IV data.</param>
		byte[][] DeriveKeyAndIV(TargetKeyType keyType, int keySizeInBytes, int ivSizeInBytes);
	}
}

