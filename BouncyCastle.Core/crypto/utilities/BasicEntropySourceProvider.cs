using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Utilities
{
	/// <summary>
	/// An EntropySourceProvider where entropy generation is based on a SecureRandom output using SecureRandom.generateSeed().
	/// </summary>
	public class BasicEntropySourceProvider: IEntropySourceProvider
	{
		private readonly SecureRandom _sr;
		private readonly bool      _predictionResistant;

		/// <summary>
		/// Create a entropy source provider based on the passed in SecureRandom.
		/// </summary>
		/// <param name="random">The SecureRandom to base EntropySource construction on.</param>
		/// <param name="isPredictionResistant">Boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is)</param>
		public BasicEntropySourceProvider(SecureRandom random, bool isPredictionResistant)
		{
			_sr = random;
			_predictionResistant = isPredictionResistant;
		}
			
		/// <summary>
		/// Return an entropy source that will create bitsRequired bits of entropy on each invocation of getEntropy().
		/// </summary>
		/// <param name="bitsRequired">Size (in bits) of entropy to be created by the provided source.</param>
		/// <returns>An EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method.</returns>
		public IEntropySource Get(int bitsRequired)
		{
			return new Source (bitsRequired, _sr, _predictionResistant);
		}

		internal class Source: IEntropySource
		{
			private readonly int bitsRequired;
			private readonly SecureRandom _sr;
			private readonly bool      _predictionResistant;

			internal Source(int bitsRequired, SecureRandom sr, bool predictionResistant)
			{
				this.bitsRequired = bitsRequired;
				this._sr = sr;
				this._predictionResistant = predictionResistant;
			}

			public bool IsPredictionResistant
			{
				get {
					return _predictionResistant;
				}
			}

			public byte[] GetEntropy()
			{
				return _sr.GenerateSeed((bitsRequired + 7) / 8);
			}

			public int EntropySize
			{
				get {
					return bitsRequired;
				}
			}
		}
	}
}

