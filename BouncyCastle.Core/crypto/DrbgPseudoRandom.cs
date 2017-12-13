
namespace Org.BouncyCastle.Crypto
{
	internal class DrbgPseudoRandom: IDrbg
	{
		private readonly Algorithm algorithm;
		private readonly IDrbgProvider drbgProvider;
		private readonly IEntropySource entropySource;

		private IDrbg drbg;

		internal DrbgPseudoRandom(Algorithm algorithm, IEntropySource entropySource, IDrbgProvider drbgProvider)
		{
			this.algorithm = algorithm;
			this.entropySource = new ContinuousTestingEntropySource(entropySource);
			this.drbgProvider = drbgProvider;
		}

        /// <summary>
        /// Return the block size of the underlying DRBG
        /// </summary>
        public int BlockSize
		{
			get {
				
				lock (this)
				{
					lazyInitDRBG ();
				}

				return drbg.BlockSize;
			}
		}

		public int SecurityStrength
		{
			get {
				lock (this)
				{
					lazyInitDRBG ();
				}

				return drbg.SecurityStrength;
			}
		}

		private void lazyInitDRBG()
		{
			if (drbg == null)
			{
				drbg = drbgProvider.Get(entropySource);
                // FSM_STATE:5.6, "DRBG HEALTH CHECKS", "The module is performing DRBG Health Check self-test"
                // FSM_TRANS:5.5, "CONDITIONAL TEST", "DRBG HEALTH CHECKS", "Invoke DRBG Health Check"
                SelfTestExecutor.Validate(algorithm, drbg.CreateSelfTest(algorithm));   // instance health test
				// FSM_TRANS:5.6, "DRBG HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Health Check successful"
			}
		}

		public int Generate(byte[] output, byte[] additionalInput, bool predictionResistant)
		{
			lock (this)
			{
				lazyInitDRBG();

                if (predictionResistant)
                {
                    // FSM_STATE:5.7, "DRBG RESEED HEALTH CHECK", "The module is performing DRBG Reseed Health Check self-test"
                    // FSM_TRANS:5.7, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                    SelfTestExecutor.Validate(algorithm, drbg.CreateReseedSelfTest(algorithm));    // reseed health test
                    // FSM_TRANS:5.8, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                }

                // check if a reseed is required...
                if (drbg.Generate(output, additionalInput, predictionResistant) < 0)
				{
                    // FSM_STATE:5.7, "DRBG RESEED HEALTH CHECK", "The module is performing DRBG Reseed Health Check self-test"
                    // FSM_TRANS:5.7, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                    SelfTestExecutor.Validate(algorithm, drbg.CreateReseedSelfTest(algorithm));    // reseed health test
					// FSM_TRANS:5.8, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"

					drbg.Reseed(null);
					return drbg.Generate(output, additionalInput, predictionResistant);
				}

				return output.Length;
			}
		}

		public void Reseed(byte[] additionalInput)
		{
			lock (this)
			{
				lazyInitDRBG();

                // FSM_STATE:5.7, "DRBG RESEED HEALTH CHECK", "The module is performing DRBG Reseed Health Check self-test"
                // FSM_TRANS:5.7, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                SelfTestExecutor.Validate(algorithm, drbg.CreateReseedSelfTest(algorithm));   // reseed health test.
                // FSM_TRANS:5.8, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"

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
	}
}

