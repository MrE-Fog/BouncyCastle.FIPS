using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Utilities.Test
{
	public class FixedEntropySourceProvider: IEntropySourceProvider
	{
		private readonly byte[] data;
		private readonly bool isPredictionResistant;

		public FixedEntropySourceProvider(byte[] data, bool isPredictionResistant)
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

			private bool first = true;
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

				// we assume continuous testing
				if (first)
				{
					for (int i = 0; i != rv.Length; i++)
					{
						rv[i] ^= 0xff;
					}
					first = false;
				}
				else
				{
					index += (bitsRequired + 7) / 8;
				}

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

