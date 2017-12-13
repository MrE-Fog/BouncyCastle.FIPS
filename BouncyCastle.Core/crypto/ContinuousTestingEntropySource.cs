using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
	internal class ContinuousTestingEntropySource: IEntropySource
	{
		private readonly IEntropySource entropySource;

		private byte[] buf;

		public ContinuousTestingEntropySource(IEntropySource entropySource)
		{
			this.entropySource = entropySource;
		}

		public bool IsPredictionResistant
		{
			get {
				return entropySource.IsPredictionResistant;
			}
		}

		public byte[] GetEntropy()
		{
			lock (this)
			{
				byte[] nxt;

				if (buf == null)
				{
					buf = entropySource.GetEntropy();
				}

				// FSM_STATE:5.1, "CONTINUOUS NDRBG TEST", "The module is performing Continuous NDRNG self-test"
				// FSM_TRANS:5.1, "CONDITIONAL TEST", "CONTINUOUS NDRNG TEST", "Invoke Continuous NDRNG test"
				nxt = entropySource.GetEntropy();

				if (Arrays.AreEqual(nxt, buf))
				{
					CryptoStatus.MoveToErrorStatus("Duplicate block detected in EntropySource output");
				}
				// FSM_TRANS:5.2, "CONTINUOUS NDRNG TEST", "CONDITIONAL TEST", "Continuous NDRNG test successful"
				Array.Copy(nxt, 0, buf, 0, buf.Length);

				return nxt;
			}
		}

		public int EntropySize
		{
			get {
				return entropySource.EntropySize;
			}
		}
	}
}

