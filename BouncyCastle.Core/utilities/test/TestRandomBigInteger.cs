using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Utilities.Test
{
	/// <summary>
	/// A fixed secure random designed to return data for someone needing to create a single BigInteger.
	/// </summary>
	public class TestRandomBigInteger: FixedSecureRandom
	{
		/// <summary>
		/// Constructor from a base 10 represention of a BigInteger.
		/// </summary>
		/// <param name="encoding">A base 10 represention of a BigInteger.</param>
		public TestRandomBigInteger(String encoding): this(encoding, 10)
		{
		}
			
		/// <summary>
		/// Constructor from a base radix represention of a BigInteger.
		/// </summary>
		/// <param name="encoding">A String BigInteger of base radix.</param>
		/// <param name="radix">The radix to use.</param>
		public TestRandomBigInteger(String encoding, int radix): base(new FixedSecureRandom.BigInteger(BigIntegers.AsUnsignedByteArray(new Org.BouncyCastle.Math.BigInteger(encoding, radix))))
		{
		}
			
		/// <summary>
		/// Constructor based on a byte array.
		/// </summary>
		/// <param name="encoding">A 2's complement representation of the BigInteger.</param>
		public TestRandomBigInteger(byte[] encoding): base(new FixedSecureRandom.BigInteger(encoding))
		{
		}
	}
}

