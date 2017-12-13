using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Fips
{
	internal class DrbgKatFixedEntropySourceProvider
        : IEntropySourceProvider
	{
		private readonly byte[] data;
		private readonly bool isPredictionResistant;

		public DrbgKatFixedEntropySourceProvider(byte[] data, bool isPredictionResistant)
		{
			this.data = data;
			this.isPredictionResistant = isPredictionResistant;
		}

		public IEntropySource Get(int bitsRequired)
		{
			return new EntropySource (bitsRequired, data, isPredictionResistant);
		}

		internal class EntropySource: IEntropySource
		{
			private readonly int bitsRequired;
			private readonly byte[] data;
			private readonly bool isPredictionResistant;

			private int index = 0;

			internal EntropySource(int bitsRequired, byte[] data, bool isPredictionResistant)
			{
				this.data = data;
				this.isPredictionResistant = isPredictionResistant;
				this.bitsRequired = bitsRequired;
			}

			public bool IsPredictionResistant
			{
				get {
					return isPredictionResistant;
				}
			}

			public byte[] GetEntropy()
			{
				byte[] rv = new byte[(bitsRequired + 7) / 8];

				Array.Copy(data, index, rv, 0, rv.Length);

				index += (bitsRequired + 7) / 8;

				return rv;
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

