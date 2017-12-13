using System;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// The target key type a deriver is trying to produce a key for.
	/// </summary>
	public enum TargetKeyType
	{
		/// <summary>
		/// Target key for a symmetric cipher.
		/// </summary>
		CIPHER,
		/// <summary>
		/// Target key for a MAC.
		/// </summary>
		MAC,
	}
}

