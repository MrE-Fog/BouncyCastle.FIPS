using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Fips
{
	public class FipsSecureRandom: SecureRandom
	{
		private readonly SecureRandom randomSource;
		private readonly IDrbg drbg;
		private readonly bool predictionResistant;

		internal FipsSecureRandom(SecureRandom randomSource, IDrbg drbg, bool predictionResistant)
		{
			//super(new RandomSpi(randomSource, drbg, predictionResistant), new RandomProvider());
			this.randomSource = randomSource;
			this.drbg = drbg;
			this.predictionResistant = predictionResistant;
		}

		public override void SetSeed(long seed)
		{
			// this will happen when SecureRandom() is created
			if (drbg != null)
			{
				lock (drbg)
				{
					this.randomSource.SetSeed(seed);
				}
			}
		}

		public override void NextBytes(byte[] bytes)
		{
			lock (drbg)
			{
				// check if a reseed is required...
				if (drbg.Generate(bytes, null, predictionResistant) < 0)
				{
					drbg.Reseed(null);
					drbg.Generate(bytes, null, predictionResistant);
				}
			}
		}

		public void NextBytes(byte[] bytes, byte[] additionalInput)
		{
			lock (drbg)
			{
				// check if a reseed is required...
				if (drbg.Generate(bytes, additionalInput, predictionResistant) < 0)
				{
					drbg.Reseed(null);
					drbg.Generate(bytes, additionalInput, predictionResistant);
				}
			}
		}
			
		/// <summary>
		/// Return the block size of the underlying DRBG.
		/// </summary>
		/// <value>Number of bits produced each cycle.</value>
		public int BlockSize
		{
			get {
				return drbg.BlockSize;
			}
		}
			
		/// <summary>
		/// Return the security strength of the DRBG.
		/// </summary>
		/// <value>The security strength (in bits) of the DRBG.</value>
		internal int SecurityStrength
		{
			get {
				return drbg.SecurityStrength;
			}
		}

		/// <summary>
		/// Force a reseed of this instance.
		/// </summary>
		public void Reseed()
		{
			drbg.Reseed(null);
		}
			
		/// <summary>
		/// Force a reseed with additional input.
		/// </summary>
		/// <param name="additionalInput">Additional input to be used in conjunction with reseed.</param>
		public void Reseed(byte[] additionalInput)
		{
			drbg.Reseed(additionalInput);
		}
	}
}

