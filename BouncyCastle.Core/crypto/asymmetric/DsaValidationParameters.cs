using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	/// <summary>
	/// Validation parameters for confirming DSA parameter generation.
	/// </summary>
	public class DsaValidationParameters
	{
		private int usageIndex;
		private byte[]  seed;
		private int     counter;

		/// <summary>
		/// Base constructor - a seed, the counter will be set to -1.
		/// </summary>
		/// <param name="seed">The seed used to generate the parameters.</param>
		public DsaValidationParameters(
			byte[] seed): this(seed, -1, -1)
		{
		}
			
		/// <summary>
		/// Constructor with a seed and a (p, q) counter for it.
		/// </summary>
		/// <param name="seed">The seed used to generate the parameters.</param>
		/// <param name="counter">The counter value associated with using the seed to generate the parameters.</param>
		public DsaValidationParameters(
			byte[] seed,
			int counter): this(seed, counter, -1)
		{
		}
			
		/// <summary>
		/// Base constructor with a seed, counter, and usage index.
		/// </summary>
		/// <param name="seed">The seed value.</param>
		/// <param name="counter">(p, q) counter - -1 if not avaliable.</param>
		/// <param name="usageIndex">The usage index.</param>
		public DsaValidationParameters(
			byte[] seed,
			int counter,
			int usageIndex)
		{
			this.seed = Arrays.Clone(seed);
			this.counter = counter;
			this.usageIndex = usageIndex;
		}
			
		/// <summary>
		/// Return the (p, q) counter value.
		/// </summary>
		/// <value>The (p, q) counter value, -1 if unavailable.</value>
		public int Counter
		{
			get {
				return counter;
			}
		}

		/// <summary>
		/// Return the seed used for the parameter generation.
		/// </summary>
		/// <returns>The the seed array.</returns>
		public byte[] GetSeed()
		{
			return Arrays.Clone(seed);
		}
			
		/// <summary>
		/// Return the usage index, -1 if none given.
		/// </summary>
		/// <value>The usage index.</value>
		public int UsageIndex
		{
			get {
				return usageIndex;
			}
		}

		public override int GetHashCode()
		{
			int code = this.counter;

			code += 37 * Arrays.GetHashCode(seed);
			code += 37 * usageIndex;

			return code;
		}

		public override bool Equals(
			Object o)
		{
			if (!(o is DsaValidationParameters))
			{
				return false;
			}

			DsaValidationParameters other = (DsaValidationParameters)o;

			if (other.counter != this.counter)
			{
				return false;
			}

			if (other.usageIndex != this.usageIndex)
			{
				return false;
			}

			return Arrays.AreEqual(this.seed, other.seed);
		}
	}
}

