using System;
using System.Collections;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Fips
{
	internal class HashSP800Drbg: ISP80090Drbg
	{
		private readonly static byte[]     ZERO = { 0x00 };
		private readonly static byte[]     ONE = { 0x01 };

		private readonly static long       RESEED_MAX = 1L << (48 - 1);
		private readonly static int        MAX_BITS_REQUEST = 1 << (19 - 1);

		private static readonly IDictionary seedlens = Platform.CreateHashtable();
		private static readonly IDictionary kats = Platform.CreateHashtable();
		private static readonly IDictionary reseedVs = Platform.CreateHashtable();
		private static readonly IDictionary reseedKats = Platform.CreateHashtable();

		static HashSP800Drbg()
		{
			seedlens.Add("SHA-1", 440);
			seedlens.Add("SHA-224", 440);
			seedlens.Add("SHA-256", 440);
			seedlens.Add("SHA-512/256", 440);
			seedlens.Add("SHA-512/224", 440);
			seedlens.Add("SHA-384", 888);
			seedlens.Add("SHA-512", 888);

			kats.Add("SHA-1", new byte[][] {
				Hex.Decode("61a50e3970bdb72c7ebf2a6225519ea2f324148123a3503443ec80993a62c4ea6528ff4f5f4fe778"),
				Hex.Decode("71adf1e44be3e0a6af022d6e79aad42a99d8261ef41e06c3efed4ac8bf9687e8e1bab92da552e109") });

			kats.Add("SHA-224", new byte[][] {
				Hex.Decode("5be6d688ee42f489506a5a3407380325c633627f8c2458c1d82fc9a3db5787565c9d6c5e0e32b5f0"),
				Hex.Decode("3726e8c434f91c2fdd6d80621e79005f38320932ca9da5edad095eeff18693b7908f936268e20b58") });

			kats.Add("SHA-256", new byte[][] {
				Hex.Decode("788dd696649d97295de7ed10a2c55104abb36cd0f262abdc2b8b2b183a3602c3f7513d2a4893b759"),
				Hex.Decode("3db6a852f92035e4890fa53438cf8070020a95ae19f1098f98a4d4bdb65f3c5c2dd4c9fb5483410d") });

			kats.Add("SHA-384", new byte[][] {
				Hex.Decode("0536f72f4123b8e438981912b3c60b09d1303a93b7cbe4af13cd3ae01d389720ff687916135bb254"),
				Hex.Decode("80ae6b3d1a120d9f58d427a178c7d73d429758f6039962b66f8afbc7fa758228b13b8f5829588cd6") });

			kats.Add("SHA-512", new byte[][] {
				Hex.Decode("ca8387ba70bc7f8cb71e5d25703972ed58c7b5c81649050cdc17a9f646f7bd57857ca715e411d2ca"),
				Hex.Decode("ce2fe5ba54cde888bee0f4863ca70b258ab6e2be31523542a4da66033433fb8e7e394b28198daa1e") });

			kats.Add("SHA-512(224)", new byte[][] {
				Hex.Decode("d2a49d96a75e30d65da621aaf5e3e84b1c3d5313aefa2d276c9e1d836615217b67d766ccd342e956"),
				Hex.Decode("32195006d69ed3cdef3d6e5af94ae91c0c3282202b0bfebdc11cc9d4c02f534b0f6bb9a8b8f2b7fe") });

			kats.Add("SHA-512(256)", new byte[][] {
				Hex.Decode("881b2a06f0f23921341819bf9cf78ed122850a80ae6c6eaf84e84600d756486c442305a495db0d96"),
				Hex.Decode("c9351dfad36fd8309a5bd598ac4ee9ca22297263f21c21d8481acefea97f5e508134f43959ac7f90") });

			reseedVs.Add("SHA-1", Hex.Decode("3c01bdbb26f358bab27f267924aa2c9a03fcfdb8"));

			reseedVs.Add("SHA-224", Hex.Decode("107c5072b799c4771f328304cfe1ebb375eb6ea7f35a3aa753836fad"));

			reseedVs.Add("SHA-256", Hex.Decode("b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78"));

			reseedVs.Add("SHA-384", Hex.Decode("1e02dc92a41db610c9bcdc9b5935d1fb9be5639116f6c67e97bc1a3ac649753baba7ba021c813e1fe20c0480213ad371"));

			reseedVs.Add("SHA-512", Hex.Decode("397118fdac8d83ad98813c50759c85b8c47565d8268bf10da483153b747a74743a58a90e85aa9f705ce6984ffc128db567489817e4092d050d8a1cc596ddc119"));

			reseedVs.Add("SHA-512(224)", Hex.Decode("2a2aa10c3ca33a979d6cc7d36f94425fb72a09d3d7137c8b9b5b4474"));

			reseedVs.Add("SHA-512(256)", Hex.Decode("625c3e642852cb343b9b06eae14b47a7da0fd292a7be7b8a251208a65271af36"));

			reseedKats.Add("SHA-1", new byte[][] {
				Hex.Decode("657d09ba244bf82e69ee1f860d9bfbf53aebd25827aab770e1f33d4d7bd34596d5f1be2ff0dcde4c"),
				Hex.Decode("01b3e73d42c180963004e6d4d31f38f1bfa3a815c8571f4d9bbed56d5f8afc8f1da145d36232554f") });

			reseedKats.Add("SHA-224", new byte[][] {
				Hex.Decode("267c1bc6462b4157320dfe212118370788cff8124af984c3aac5f543228ad69ebdbbf401db50de77"),
				Hex.Decode("9b7b7b267d3d7bd6cead4242b9bae3bcdf812901bcff06dca582dfa01e2db3cada2e77f665db1e20") });

			reseedKats.Add("SHA-256", new byte[][] {
				Hex.Decode("05e4940b7cbb02e2bfa3cb03e369379f068ff7d51595403c41579791ee585605b8c4a676bf3a9b52"),
				Hex.Decode("dbb50e0e562f3d83fee0c1f020ffbc04f2eaa8e78009cae0eb8c40628a25dcb4ac096732cc2fa1b4") });

			reseedKats.Add("SHA-384", new byte[][] {
				Hex.Decode("5ad1f8c6d18dc235cdb306613926eb9ba67fc910ee7d5483ccc4c9717c576342945aaead78a99bbb"),
				Hex.Decode("03a45f886270781455ff6242d2052b5d84fcea57d95de31fdbd7f973d4027586972da7028fa4c820") });

			reseedKats.Add("SHA-512", new byte[][] {
				Hex.Decode("147abe77d9b19bf6331691eeb3571e55afb406d1ddcd7aa5f1b3de71f0d3eb6949ea580764588000"),
				Hex.Decode("59c18dd408b82f930411bfdeea503d0154a77263c934d7888677ce34018307d4dd035effed210979") });

			reseedKats.Add("SHA-512(224)", new byte[][] {
				Hex.Decode("b8517f43fb91321ee4b6e2d9478970b4fa727518e0176e97536dbb3a55cba46a29557a8dd9db26d4"),
				Hex.Decode("d9d32c83c6586c3ab235830367733fa405ade3c8ff6d24ea28bf6ba3f4ab4784336a32a2a8535be5") });

			reseedKats.Add("SHA-512(256)", new byte[][] {
				Hex.Decode("a33a0d6840f8be385f9aa683cb01e0e0b4d36a1de33e2ea931c015f86f231f574569452950537db7"),
				Hex.Decode("e862780ba48bab8df070be0ca429299a9c744cfa84acb578be5f86155719a23aab6c92b432e9f85b") });
		}

		private IDigest        mDigest;
		private byte[]         mV;
		private byte[]         mC;
		private long           mReseedCounter;
		private IEntropySource mEntropySource;
		private int            mSecurityStrength;
		private int            mSeedLength;

		/**
         * Construct a SP800-90A Hash DRBG.
         * <p>
         * Minimum entropy requirement is the security strength requested.
         * </p>
         * @param digest  source digest to use for DRB stream.
         * @param securityStrength security strength required (in bits)
         * @param entropySource source of entropy to use for seeding/reseeding.
         * @param personalizationString personalization string to distinguish this DRBG (may be null).
         * @param nonce nonce to further distinguish this DRBG (may be null).
         */
		public HashSP800Drbg(IDigest digest, int securityStrength, IEntropySource entropySource, byte[] personalizationString, byte[] nonce)
		{
			init(digest, securityStrength, entropySource, personalizationString, nonce);
		}

        ~HashSP800Drbg()
        {
            if (mV != null)
            {
                Array.Clear(mV, 0, mV.Length);
            }
            if (mC != null)
            {
                Array.Clear(mC, 0, mC.Length);
            }
            mReseedCounter = 0;
        }

        private void init(IDigest digest, int securityStrength, IEntropySource entropySource, byte[] personalizationString, byte[] nonce)
		{
			if (securityStrength > DrbgUtilities.GetMaxSecurityStrength(digest))
			{
				throw new ArgumentException("Requested security strength is not supported by the derivation function");
			}

			if (entropySource.EntropySize < securityStrength)
			{
				throw new ArgumentException("Not enough entropy for security strength required");
			}

			mDigest = digest;
			mEntropySource = entropySource;
			mSecurityStrength = securityStrength;
			mSeedLength = (int)seedlens[digest.AlgorithmName];

			// 1. seed_material = entropy_input || nonce || personalization_string.
			// 2. seed = Hash_df (seed_material, seedlen).
			// 3. V = seed.
			// 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
			// of zeros.
			// 5. reseed_counter = 1.
			// 6. Return V, C, and reseed_counter as the initial_working_state

			byte[] entropy = getEntropy();
			byte[] seedMaterial = Arrays.ConcatenateAll(entropy, nonce, personalizationString);
			Arrays.Fill(entropy, (byte)0);

			reseedFromSeedMaterial(seedMaterial);
		}

		/**
         * Return the block size (in bits) of the DRBG.
         *
         * @return the number of bits produced on each internal round of the DRBG.
         */
		public int BlockSize
		{
			get { return mDigest.GetDigestSize() * 8; }
		}

		/**
         * Return the security strength of the DRBG.
         *
         * @return the security strength (in bits) of the DRBG.
         */
		public int SecurityStrength
		{
			get { return mSecurityStrength; }
		}

		/**
         * Populate a passed in array with random data.
         *
         * @param output output array for generated bits.
         * @param additionalInput additional input to be added to the DRBG in this step.
         * @param predictionResistant true if a reseed should be forced, false otherwise.
         *
         * @return number of bits generated, -1 if a reseed required.
         */
		public int Generate(byte[] output, byte[] additionalInput, bool predictionResistant)
		{
			// 1. If reseed_counter > reseed_interval, then return an indication that a
			// reseed is required.
			// 2. If (additional_input != Null), then do
			// 2.1 w = Hash (0x02 || V || additional_input).
			// 2.2 V = (V + w) mod 2^seedlen
			// .
			// 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
			// 4. H = Hash (0x03 || V).
			// 5. V = (V + H + C + reseed_counter) mod 2^seedlen
			// .
			// 6. reseed_counter = reseed_counter + 1.
			// 7. Return SUCCESS, returned_bits, and the new values of V, C, and
			// reseed_counter for the new_working_state.
			int numberOfBits = output.Length*8;

			if (numberOfBits > MAX_BITS_REQUEST)
			{
				throw new ArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST);
			}

            if (predictionResistant)
            {
                Reseed(additionalInput);
                additionalInput = null;
            }

            if (mReseedCounter > RESEED_MAX)
			{
				return -1;
			}

			// 2.
			if (additionalInput != null)
			{
				byte[] newInput = new byte[1 + mV.Length + additionalInput.Length];
				newInput[0] = 0x02;
				Array.Copy(mV, 0, newInput, 1, mV.Length);
				// TODO: inOff / inLength
				Array.Copy(additionalInput, 0, newInput, 1 + mV.Length, additionalInput.Length);
				byte[] w = Hash(newInput);

				addTo(mV, w);
			}

			// 3.
			byte[] rv = hashgen(mV, numberOfBits);

			// 4.
			byte[] subH = new byte[mV.Length + 1];
			Array.Copy(mV, 0, subH, 1, mV.Length);
			subH[0] = 0x03;

			byte[] H = Hash(subH);

			// 5.
			addTo(mV, H);
			addTo(mV, mC);
			byte[] c = new byte[4];
			c[0] = (byte)(mReseedCounter >> 24);
			c[1] = (byte)(mReseedCounter >> 16);
			c[2] = (byte)(mReseedCounter >> 8);
			c[3] = (byte)mReseedCounter;

			addTo(mV, c);

			mReseedCounter++;

			Array.Copy(rv, 0, output, 0, output.Length);

			return numberOfBits;
		}

		// this will always add the shorter length byte array mathematically to the
		// longer length byte array.
		// be careful....
		private void addTo(byte[] longer, byte[] shorter)
		{
			int carry = 0;
			for (int i=1;i <= shorter.Length; i++) // warning
			{
				int res = (longer[longer.Length-i] & 0xff) + (shorter[shorter.Length-i] & 0xff) + carry;
				carry = (res > 0xff) ? 1 : 0;
				longer[longer.Length-i] = (byte)res;
			}

			for (int i=shorter.Length+1; i <= longer.Length; i++) // warning
			{
				int res = (longer[longer.Length-i] & 0xff) + carry;
				carry = (res > 0xff) ? 1 : 0;
				longer[longer.Length-i] = (byte)res;
			}
		}

		/**
      * Reseed the DRBG.
      *
      * @param additionalInput additional input to be added to the DRBG in this step.
      */
		public void Reseed(byte[] additionalInput)
		{
			// 1. seed_material = 0x01 || V || entropy_input || additional_input.
			//
			// 2. seed = Hash_df (seed_material, seedlen).
			//
			// 3. V = seed.
			//
			// 4. C = Hash_df ((0x00 || V), seedlen).
			//
			// 5. reseed_counter = 1.
			//
			// 6. Return V, C, and reseed_counter for the new_working_state.
			//
			// Comment: Precede with a byte of all zeros.

			byte[] entropy = getEntropy();
			byte[] seedMaterial = Arrays.ConcatenateAll(ONE, mV, entropy, additionalInput);
			Arrays.Fill(entropy, (byte)0);

			reseedFromSeedMaterial(seedMaterial);
		}

		private void reseedFromSeedMaterial(byte[] seedMaterial)
		{
			mV = hashSeedMaterial(seedMaterial);
			mC = hashSeedMaterial(Arrays.Concatenate(ZERO, mV));
			mReseedCounter = 1;
		}

		private byte[] hashSeedMaterial(byte[] seedMaterial)
		{
			try
			{
				return DrbgUtilities.HashDF(mDigest, seedMaterial, mSeedLength);
			}
			finally
			{
				Arrays.Fill(seedMaterial, (byte)0);
			}
		}

		private byte[] getEntropy()
		{
			byte[] entropy = mEntropySource.GetEntropy();
			if (entropy == null || entropy.Length < (mSecurityStrength + 7) / 8)
			{
				throw new InvalidOperationException("Insufficient entropy provided by entropy source");
			}
			return entropy;
		}

        public VariantInternalKatTest CreateSelfTest(Algorithm algorithm)
		{
			return new SelfTest (algorithm, this);
		}

		private class SelfTest: VariantInternalKatTest
		{
			private readonly HashSP800Drbg parent;

			internal SelfTest(Algorithm algorithm, HashSP800Drbg parent) : base(algorithm)
			{
				this.parent = parent;
			}

			internal override void Evaluate()
			{
				byte[] origV = parent.mV;
				byte[] origC = parent.mC;
				long origReseedCounter = parent.mReseedCounter;
				IEntropySource origEntropySource = parent.mEntropySource;
				int origSeedLength = parent.mSeedLength;
				int origSecurityStrength = parent.mSecurityStrength;

				try
				{
					byte[] personalization = Hex.Decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");
					byte[] nonce = Hex.Decode("2021222324");

					int entropyStrength = DrbgUtilities.GetMaxSecurityStrength(parent.mDigest);

					byte[][] expected = (byte[][])kats[algorithm.Name];

					parent.init(parent.mDigest, parent.mSecurityStrength, new DrbgUtilities.KatEntropyProvider().Get(entropyStrength), personalization, nonce);

					byte[] output = new byte[expected[0].Length];

					parent.Generate(output, null, true);
					if (!Arrays.AreEqual(expected[0], output))
					{
						Fail("DRBG Block 1 KAT failure");
					}

					output = new byte[expected[1].Length];

					parent.Generate(output, null, true);
					if (!Arrays.AreEqual(expected[1], output))
					{
						Fail("DRBG Block 2 KAT failure");
					}

					try
					{
						parent.init(parent.mDigest, parent.mSecurityStrength, new DrbgUtilities.LyingEntropySource(entropyStrength), personalization, nonce);

						Fail("DRBG LyingEntropySource not detected in init");
					}
					catch (InvalidOperationException e)
					{
						if (!e.Message.Equals("Insufficient entropy provided by entropy source"))
						{
							Fail("DRBG self test failed init entropy check");
						}
					}

					try
					{
						parent.init(parent.mDigest, parent.mSecurityStrength, new DrbgUtilities.LyingEntropySource(20), personalization, nonce);

						Fail("DRBG insufficient EntropySource not detected");
					}
					catch (ArgumentException e)
					{
						if (!e.Message.Equals("Not enough entropy for security strength required"))
						{
							Fail("DRBG self test failed init entropy check");
						}
					}

					try
					{
						parent.mEntropySource = new DrbgUtilities.LyingEntropySource(entropyStrength);

						parent.Reseed(null);

						Fail("DRBG LyingEntropySource not detected in reseed");
					}
					catch (InvalidOperationException e)
					{
						if (!e.Message.Equals("Insufficient entropy provided by entropy source"))
						{
							Fail("DRBG self test failed reseed entropy check");
						}
					}

					try
					{
						parent.init(parent.mDigest, entropyStrength + 1, new DrbgUtilities.KatEntropyProvider().Get(entropyStrength), personalization, nonce);

						Fail("DRBG successful initialise with too high security strength");
					}
					catch (ArgumentException e)
					{
						if (!e.Message.Equals("Requested security strength is not supported by the derivation function"))
						{
							Fail("DRBG self test failed init security strength check");
						}
					}
				}
				finally
				{
					parent.mV = origV;
					parent.mC = origC;
					parent.mReseedCounter = origReseedCounter;
					parent.mEntropySource = origEntropySource;
					parent.mSeedLength = origSeedLength;
					parent.mSecurityStrength = origSecurityStrength;
				}
			}
		}


		public VariantInternalKatTest CreateReseedSelfTest(Algorithm algorithm)
		{
			return new ReseedSelfTest(algorithm, this);
		}

		private class ReseedSelfTest: VariantInternalKatTest
		{
			private readonly HashSP800Drbg parent;

			internal ReseedSelfTest(Algorithm algorithm, HashSP800Drbg parent) : base(algorithm)
			{
				this.parent = parent;
			}

			internal override void Evaluate()
			{
				byte[] origV = parent.mV;
				byte[] origC = parent.mC;
				long origReseedCounter = parent.mReseedCounter;
				IEntropySource origEntropySource = parent.mEntropySource;
				int origSeedLength = parent.mSeedLength;
				int origSecurityStrength = parent.mSecurityStrength;

				try
				{
					byte[] additionalInput = Hex.Decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576");

					int entropyStrength = DrbgUtilities.GetMaxSecurityStrength(parent.mDigest);

					byte[][] expected = (byte[][])reseedKats[algorithm.Name];

					parent.mV = Arrays.Clone((byte[])reseedVs[algorithm.Name]);

					parent.mEntropySource = new DrbgUtilities.KatEntropyProvider().Get(entropyStrength);

					parent.Reseed(additionalInput);

					if (parent.mReseedCounter != 1)
					{
						Fail("DRBG reseedCounter failed to reset");
					}

					byte[] output = new byte[expected[0].Length];

					parent.Generate(output, null, false);
					if (!Arrays.AreEqual(expected[0], output))
					{
						Fail("DRBG Block 1 reseed KAT failure");
					}

					output = new byte[expected[1].Length];

					parent.Generate(output, null, false);
					if (!Arrays.AreEqual(expected[1], output))
					{
						Fail("DRBG Block 2 reseed KAT failure");
					}

					try
					{
						parent.mEntropySource = new DrbgUtilities.LyingEntropySource(entropyStrength);

						parent.Reseed(null);

						Fail("DRBG LyingEntropySource not detected on reseed");
					}
					catch (InvalidOperationException e)
					{
						if (!e.Message.Equals("Insufficient entropy provided by entropy source"))
						{
							Fail("DRBG self test failed reseed entropy check");
						}
					}
				}
				finally
				{
					parent.mV = origV;
					parent.mC = origC;
					parent.mReseedCounter = origReseedCounter;
					parent.mEntropySource = origEntropySource;
					parent.mSeedLength = origSeedLength;
					parent.mSecurityStrength = origSecurityStrength;
				}
			}
		}

		private byte[] Hash(byte[] input)
		{
			byte[] hash = new byte[mDigest.GetDigestSize()];
			DoHash(input, hash);
			return hash;
		}

		private void DoHash(byte[] input, byte[] output)
		{
			mDigest.BlockUpdate(input, 0, input.Length);
			mDigest.DoFinal(output, 0);
		}

		// 1. m = [requested_number_of_bits / outlen]
		// 2. data = V.
		// 3. W = the Null string.
		// 4. For i = 1 to m
		// 4.1 wi = Hash (data).
		// 4.2 W = W || wi.
		// 4.3 data = (data + 1) mod 2^seedlen
		// .
		// 5. returned_bits = Leftmost (requested_no_of_bits) bits of W.
		private byte[] hashgen(byte[] input, int lengthInBits)
		{
			int digestSize = mDigest.GetDigestSize();
			int m = (lengthInBits / 8) / digestSize;

			byte[] data = new byte[input.Length];
			Array.Copy(input, 0, data, 0, input.Length);

			byte[] W = new byte[lengthInBits / 8];

			byte[] dig = new byte[mDigest.GetDigestSize()];
			for (int i = 0; i <= m; i++)
			{
				DoHash(data, dig);

				int bytesToCopy = ((W.Length - i * dig.Length) > dig.Length)
					? dig.Length
					: (W.Length - i * dig.Length);
				Array.Copy(dig, 0, W, i * dig.Length, bytesToCopy);

				addTo(data, ONE);
			}

			return W;
		}
	}
}

