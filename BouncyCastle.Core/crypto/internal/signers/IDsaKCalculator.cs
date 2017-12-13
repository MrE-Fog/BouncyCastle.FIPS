using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Internal.Signers
{
	/// <summary>
	/// Interface defining calculators of K values for DSA/ECDSA.
	/// </summary>
	internal interface IDsaKCalculator
	{
		/// <summary>
		/// Return true if this calculator is deterministic, false otherwise.
		/// </summary>
		/// <value>><c>true</c> if this instance is deterministic; otherwise, <c>false</c>.</value>
		bool IsDeterministic { get; }

		/// <summary>
		/// Non-deterministic initialiser.
		/// </summary>
		/// <param name="n">The order of the DSA group.</param>
		/// <param name="random">A source of randomness.</param>
		void Init(BigInteger n, SecureRandom random);

		/// <summary>
		/// Deterministic initialiser.
		/// </summary>
		/// <param name="n">The order of the DSA group.</param>
		/// <param name="d">The DSA private value.</param>
		/// <param name="message">The message being signed.</param>
		void Init(BigInteger n, BigInteger d, byte[] message);

		/// <summary>
		/// Return the next valid value of K.
		/// </summary>
		/// <returns>A K value.</returns>
		BigInteger NextK();
	}
}
