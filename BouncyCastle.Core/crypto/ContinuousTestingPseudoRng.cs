using System;

namespace Org.BouncyCastle.Crypto
{
	internal class ContinuousTestingPseudoRng: IDrbg
	{
		// see FIPS 140-2 section 4.9.2 - we choose n as 64.
		private static readonly int MIN_RESOLUTION = 8;

		private readonly IDrbg drbg;

		private byte[] block;
		private byte[] nextBlock;
		private byte[] initialAdditionalInput;

		internal ContinuousTestingPseudoRng(IDrbg drbg, byte[] primaryAdditionalInput)
		{
			this.drbg = drbg;
			this.block = new byte[0];
			this.nextBlock = new byte[0];
			this.initialAdditionalInput = primaryAdditionalInput;
		}

		public int BlockSize
		{
			get {
				return drbg.BlockSize;
			}
		}

		public int SecurityStrength
		{
			get {
				return drbg.SecurityStrength;
			}
		}

		public int Generate(byte[] output, byte[] additionalInput, bool predictionResistant)
		{
			if (CryptoStatus.IsErrorStatus())
			{
				throw new CryptoOperationError(CryptoStatus.GetStatusMessage());
			}

			lock (this)
			{
				int rv;

				if (block.Length != output.Length)
				{
					if (block.Length < output.Length)
					{
						block = new byte[GetTestBlockSize(output.Length)];
						nextBlock = new byte[block.Length];

						if (initialAdditionalInput != null)
						{
							rv = drbg.Generate(block, initialAdditionalInput, predictionResistant);
							initialAdditionalInput = null;
						}
						else
						{
							rv = drbg.Generate(block, null, predictionResistant);
						}

						if (rv < 0)
						{
							CryptoStatus.MoveToErrorStatus("DRBG unable to initialise");
						}
					}
					else if (block.Length != MIN_RESOLUTION)
					{
						byte[] tmp = new byte[GetTestBlockSize(output.Length)];

						Array.Copy(block, block.Length - tmp.Length, tmp, 0, tmp.Length);

						block = tmp;
						nextBlock = new byte[GetTestBlockSize(output.Length)];
					}
				}

				rv = drbg.Generate(nextBlock, additionalInput, predictionResistant);
				if (rv < 0)
				{
					return rv;
				}

				// FSM_STATE:5.2, "CONTINUOUS DRBG TEST", "The module is performing Continuous DRBG self-test"
				// FSM_TRANS:5.3, "CONDITIONAL TEST", "CONTINUOUS DRBG TEST", "Invoke Continuous DRBG test"
				if (areEqual(block, nextBlock, 0))
				{
					CryptoStatus.MoveToErrorStatus("Duplicate block detected in DRBG output");
				}
				// FSM_TRANS:5.4, "CONTINUOUS DRBG TEST", "CONDITIONAL TEST", "Continuous DRBG test successful"

				// note we only return output bytes to output array when we are sure there is no issue.
				Array.Copy(nextBlock, 0, output, 0, output.Length);
				Array.Copy(nextBlock, 0, block, 0, block.Length);
			}

			if (CryptoStatus.IsErrorStatus())
			{
				throw new CryptoOperationError(CryptoStatus.GetStatusMessage());
			}

			return output.Length;
		}

		public void Reseed(byte[] additionalInput)
		{
			CryptoStatus.IsReady();

			lock (this)
			{
				block = new byte[0];
				nextBlock = new byte[0];
				drbg.Reseed(additionalInput);
			}
		}

		public VariantInternalKatTest CreateSelfTest(Algorithm algorithm)
		{
			return drbg.CreateSelfTest(algorithm);
		}

		public VariantInternalKatTest CreateReseedSelfTest(Algorithm algorithm)
		{
			return drbg.CreateReseedSelfTest(algorithm);
		}

		private bool areEqual(byte[] a, byte[] b, int bOff)
		{
			if (bOff + a.Length > b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[bOff + i])
				{
					return false;
				}
			}

			return true;
		}

		// see FIPS 140-2 section 4.9.2 - we choose n as 64.
		private static int GetTestBlockSize(int output)
		{
			if (output < MIN_RESOLUTION)
			{
				return MIN_RESOLUTION;
			}

			return output;
		}
	}
}

