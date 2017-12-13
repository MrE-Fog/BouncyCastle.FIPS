using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Fips
{
	/// <summary>
	/// Source class for FIPS approved implementations of Deterministic Random Bit Generators (DRBGs) from SP 800-90A.
	/// </summary>
	public class FipsDrbg
	{
		// package protect constructor
		private FipsDrbg()
		{

		}

		internal enum Variations
		{
			NONE,
			CTR_Triple_DES_168,
			CTR_AES_128,
			CTR_AES_192,
			CTR_AES_256
		}

        /// <summary>
        /// HASH DRBG - SHA-1
        /// </summary>
        public static readonly BuilderService Sha1 = new BuilderService(new FipsAlgorithm("SHA-1"), FipsShs.Sha1);

		/// <summary>
		/// HASH DRBG - SHA-224
		/// </summary>
		public static readonly BuilderService Sha224 = new BuilderService(new FipsAlgorithm("SHA-224"), FipsShs.Sha224);

		/// <summary>
		/// HASH DRBG - SHA-256
		/// </summary>
		public static readonly BuilderService Sha256 = new BuilderService(new FipsAlgorithm("SHA-256"), FipsShs.Sha256);

		/// <summary>
		/// HASH DRBG - SHA-384
		/// </summary>
		public static readonly BuilderService Sha384 = new BuilderService(new FipsAlgorithm("SHA-384"), FipsShs.Sha384);

		/// <summary>
		/// HASH DRBG - SHA-512
		/// </summary>
		public static readonly BuilderService Sha512 = new BuilderService(new FipsAlgorithm("SHA-512"), FipsShs.Sha512);

		/// <summary>
		/// HASH DRBG - SHA-512/224
		/// </summary>
		public static readonly BuilderService Sha512_224 = new BuilderService(new FipsAlgorithm("SHA-512(224)"), FipsShs.Sha512_224);

		/// <summary>
		/// HASH DRBG - SHA-512/256
		/// </summary>
		public static readonly BuilderService Sha512_256 = new BuilderService(new FipsAlgorithm("SHA-512(256)"), FipsShs.Sha512_256);

		/// <summary>
		/// HMAC DRBG - SHA-1
		/// </summary>
		public static readonly BuilderService Sha1HMac = new BuilderService(new FipsAlgorithm("SHA-1/HMAC"), FipsShs.Sha1HMac);

		/// <summary>
		/// HMAC DRBG - SHA-224
		/// </summary>
		public static readonly BuilderService Sha224HMac = new BuilderService(new FipsAlgorithm("SHA-224/HMAC"), FipsShs.Sha224HMac);

		/// <summary>
		/// HMAC DRBG - SHA-256
		/// </summary>
		public static readonly BuilderService Sha256HMac = new BuilderService(new FipsAlgorithm("SHA-256/HMAC"), FipsShs.Sha256HMac);

		/// <summary>
		/// HMAC DRBG - SHA-384
		/// </summary>
		public static readonly BuilderService Sha384HMac = new BuilderService(new FipsAlgorithm("SHA-384/HMAC"), FipsShs.Sha384HMac);

		/// <summary>
		/// HMAC DRBG - SHA-512
		/// </summary>
		public static readonly BuilderService Sha512HMac = new BuilderService(new FipsAlgorithm("SHA-512/HMAC"), FipsShs.Sha512HMac);

		/// <summary>
		/// HMAC DRBG - SHA-512/224
		/// </summary>
		public static readonly BuilderService Sha512_224HMac = new BuilderService(new FipsAlgorithm("SHA-512(224)/HMAC"), FipsShs.Sha512_224HMac);

		/// <summary>
		/// HMAC DRBG - SHA-512/256
		/// </summary>
		public static readonly BuilderService Sha512_256HMac = new BuilderService(new FipsAlgorithm("SHA-512(256)/HMAC"), FipsShs.Sha512_256HMac);

		/// <summary>
		/// CTR DRBG - 3-Key TripleDES
		/// </summary>
		public static readonly BuilderService CtrTripleDes168 = new BuilderService(new FipsAlgorithm("TRIPLEDES"), Variations.CTR_Triple_DES_168);

		/// <summary>
		/// CTR DRBG - 128 bit AES
		/// </summary>
		public static readonly BuilderService CtrAes128 = new BuilderService(new FipsAlgorithm("AES-128"), Variations.CTR_AES_128);

		/// <summary>
		/// CTR DRBG - 192 bit AES
		/// </summary>
		public static readonly BuilderService CtrAes192 = new BuilderService(new FipsAlgorithm("AES-192"), Variations.CTR_AES_192);

		/// <summary>
		/// CTR DRBG - 256 bit AES
		/// </summary>
		public static readonly BuilderService CtrAes256 = new BuilderService(new FipsAlgorithm("AES-256"), Variations.CTR_AES_256);

		static FipsDrbg()
		{
			// FSM_STATE:3.DRBG.0, "DRBG KAT" ,"The module is performing DRBG KAT self-test"
			// FSM_TRANS:3.DRBG.0, "POWER ON SELF-TEST", "DRBG KAT", "Invoke DRBG KAT self-test"
			DrbgStartUpTest();
			// FSM_TRANS:3.DRBG.1, "DRBG KAT", "POWER ON SELF-TEST", "DRBG KAT self-test successful completion"
		}

        /// <summary>
        /// Service class for DRBG SecureRandom builder retrieval.
        /// </summary>
        public class BuilderService: Parameters<FipsAlgorithm>, IBuilderServiceType<IDrbgBuilderService<FipsSecureRandom>>, IBuilderService<IDrbgBuilderService<FipsSecureRandom>>
        {
            private readonly FipsDigestAlgorithm digestAlg;
            private readonly Variations variation;

            internal BuilderService(FipsAlgorithm algorithm, Variations variation): base(algorithm)
			{
                this.digestAlg = null;
                this.variation = variation;
            }

            internal BuilderService(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm): base(algorithm)
			{
                this.digestAlg = digestAlgorithm;
                this.variation = Variations.NONE;
            }

            internal FipsDigestAlgorithm Digest
            {
                get { return digestAlg;  }
            }

            internal Variations Variation
            {
                get { return variation; }
            }

            Func<IParameters<Algorithm>, IDrbgBuilderService<FipsSecureRandom>> IBuilderService<IDrbgBuilderService<FipsSecureRandom>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Base(parameters as BuilderService);
            }
        }

        /// <summary>
        /// Base class for DRBG SecureRandom construction.
        /// </summary>
        internal class Base: Parameters<FipsAlgorithm>, IDrbgBuilderService<FipsSecureRandom>
        {
			private readonly FipsDigestAlgorithm digestAlg;
			private readonly Variations variation;

			internal Base(BuilderService service): base(service.Algorithm)
			{
				this.digestAlg = service.Digest;
				this.variation = service.Variation;
			}

			/// <summary>
			/// Return a builder using an EntropySourceProvider based on the default SecureRandom with
			/// predictionResistant set to false.
			/// <para>
			/// Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
			/// the default SecureRandom does for its generateSeed() call.
			/// </para>
			/// </summary>
			/// <returns>A new Builder instance.</returns>
			public IDrbgBuilder<FipsSecureRandom> FromDefaultEntropy()
			{
				SecureRandom entropySource = new SecureRandom();

				return new Builder(Algorithm, digestAlg, variation, entropySource, new BasicEntropySourceProvider(entropySource, false));
			}
				
			/// <summary>
			/// Construct a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value for prediction resistance.
			/// </summary>
			/// <returns>A new Builder instance.</returns>
			/// <param name="entropySource">A source of entropy.</param>
			/// <param name="predictionResistant">true if this entropySource is prediction resistant, false otherwise.</param>
			public IDrbgBuilder<FipsSecureRandom> FromEntropySource(SecureRandom entropySource, bool predictionResistant)
			{
				return new Builder(Algorithm, digestAlg, variation, entropySource, new BasicEntropySourceProvider(entropySource, predictionResistant));
			}
				
			/// <summary>
			/// Create a builder which makes creates the SecureRandom objects from a specified entropy source provider.
			/// <para>
			/// Note: If this method is used any calls to setSeed() in the resulting SecureRandom will be ignored.
			/// </para>
			/// </summary>
			/// <returns>A new Builder instance.</returns>
			/// <param name="entropySourceProvider">A provider of EntropySource objects.</param>
			public IDrbgBuilder<FipsSecureRandom> FromEntropySource(IEntropySourceProvider entropySourceProvider)
			{
				return new Builder(Algorithm, digestAlg, variation, null, entropySourceProvider);
			}
        }
			
		/// <summary>
		/// Builder for SecureRandom objects based on the FIPS DRBGs.
		/// </summary>
		public class Builder: IDrbgBuilder<FipsSecureRandom>
		{
			private readonly FipsAlgorithm algorithm;
			private readonly FipsDigestAlgorithm digestAlg;
			private readonly Variations variation;
			private readonly SecureRandom random;
			private readonly IEntropySourceProvider entropySourceProvider;

			private byte[] personalizationString;
			private int securityStrength = 256;
			private int entropyBitsRequired = 256;

			internal Builder(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlg, Variations variation, SecureRandom random, IEntropySourceProvider entropySourceProvider)
			{
				CryptoStatus.IsReady();

				this.algorithm = algorithm;
				this.digestAlg = digestAlg;
				this.variation = variation;
				this.random = random;
				this.entropySourceProvider = entropySourceProvider;
			}
				
			/// <summary>
			/// Set the personalization string for DRBG SecureRandoms created by this builder.
			/// </summary>
			/// <returns>The current Builder instance.</returns>
			/// <param name="personalizationString">The personalisation string for the underlying DRBG.</param>
			public IDrbgBuilder<FipsSecureRandom> SetPersonalizationString(byte[] personalizationString)
			{
				this.personalizationString = Arrays.Clone(personalizationString);

				return this;
			}
				
			/// <summary>
			/// Set the security strength required for DRBGs used in building SecureRandom objects.
			/// </summary>
			/// <returns>The current Builder instance.</returns>
			/// <param name="securityStrength">The security strength (in bits)</param>
			public IDrbgBuilder<FipsSecureRandom> SetSecurityStrength(int securityStrength)
			{
				this.securityStrength = securityStrength;

				return this;
			}
				
			/// <summary>
			/// Set the amount of entropy bits required for seeding and reseeding DRBGs used in building SecureRandom objects.
			/// </summary>
			/// <returns>The current Builder instance.</returns>
			/// <param name="entropyBitsRequired">The number of bits of entropy to be requested from the entropy source on each seed/reseed.</param>
			public IDrbgBuilder<FipsSecureRandom> SetEntropyBitsRequired(int entropyBitsRequired)
			{
				this.entropyBitsRequired = entropyBitsRequired;

				return this;
			}
				
			/// <summary>
			/// Build a SecureRandom based on a SP 800-90A DRBG.
			/// </summary>
			/// <param name="nonce">nonce value to use in DRBG construction.</param>
			/// <param name="predictionResistant">specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes.</param>
			/// <returns>a SecureRandom supported by a DRBG.</returns>
			public FipsSecureRandom Build(byte[] nonce, bool predictionResistant)
			{
				return Build(nonce, predictionResistant, null);
			}
				
			/// <summary>
			/// Build a SecureRandom based on a SP 800-90A DRBG.
			/// </summary>
			/// <param name="nonce">Nonce value to use in DRBG construction.</param>
			/// <param name="predictionResistant">Specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes.</param>
			/// <param name="additionalInput">Initial additional input to be used for generating the initial continuous health check block by the DRBG.</param>
			/// <returns>a SecureRandom supported by a DRBG.</returns>
			public FipsSecureRandom Build(byte[] nonce, bool predictionResistant, byte[] additionalInput)
			{
				return Build(algorithm, nonce, predictionResistant, additionalInput);
			}

			private FipsSecureRandom Build(FipsAlgorithm algorithm, byte[] nonce, bool predictionResistant, byte[] additionalInput)
			{
				if (digestAlg != null)
				{
					switch (digestAlg.Mode)
					{
					case AlgorithmMode.NONE:
						return new FipsSecureRandom(random, new DrbgPseudoRandom(algorithm, entropySourceProvider.Get(entropyBitsRequired), new HashDRBGProvider(digestAlg, Arrays.Clone(nonce), personalizationString, securityStrength, additionalInput)), predictionResistant);
					case AlgorithmMode.HMAC:
						return new FipsSecureRandom(random, new DrbgPseudoRandom(algorithm, entropySourceProvider.Get(entropyBitsRequired), new HMacDRBGProvider(digestAlg, Arrays.Clone(nonce), personalizationString, securityStrength, additionalInput)), predictionResistant);
					default:
						throw new ArgumentException("unknown algorithm passed to Build(): " + algorithm.Name);
					}
				}
				else
				{
					Internal.IBlockCipher cipher;
					int keySizeInBits;

					switch (variation)
					{
					case Variations.CTR_AES_128:
						cipher = FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);
						keySizeInBits = 128;
						break;
					case Variations.CTR_AES_192:
						cipher = FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);
						keySizeInBits = 192;
						break;
					case Variations.CTR_AES_256:
						cipher = FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);
						keySizeInBits = 256;
						break;
					case Variations.CTR_Triple_DES_168:
						cipher = FipsTripleDes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);
						keySizeInBits = 168;
						break;
					default:
						throw new ArgumentException("unknown algorithm passed to Build(): " + algorithm.Name);
					}

					return new FipsSecureRandom(random, new DrbgPseudoRandom(algorithm, entropySourceProvider.Get(entropyBitsRequired), new CTRDRBGProvider(cipher, keySizeInBits, Arrays.Clone(nonce), personalizationString, securityStrength, additionalInput)), predictionResistant);
				}
			}
		}

		internal class HashDRBGProvider: IDrbgProvider
		{
			private readonly IDigest digest;
			private readonly byte[] nonce;
			private readonly byte[] personalizationString;
			private readonly int securityStrength;
			private readonly byte[] primaryAdditionalInput;

			internal HashDRBGProvider(FipsDigestAlgorithm algorithm, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
			{
				CryptoStatus.IsReady();
				this.digest = FipsShs.CreateDigest(algorithm);
				this.nonce = nonce;
				this.personalizationString = personalizationString;
				this.securityStrength = securityStrength;
				this.primaryAdditionalInput = primaryAdditionalInput;
			}

			public IDrbg Get(IEntropySource entropySource)
			{
				HashSP800Drbg drbg = new HashSP800Drbg(digest, securityStrength, entropySource, personalizationString, nonce);

				return new ContinuousTestingPseudoRng(drbg, primaryAdditionalInput);
			}
		}

		internal class HMacDRBGProvider: IDrbgProvider
		{
			private readonly IMac hMac;
			private readonly byte[] nonce;
			private readonly byte[] personalizationString;
			private readonly int securityStrength;
			private readonly byte[] primaryAdditionalInput;

			internal HMacDRBGProvider(FipsDigestAlgorithm algorithm, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
			{
				CryptoStatus.IsReady();
				this.hMac = FipsShs.CreateHmac(algorithm);
				this.nonce = nonce;
				this.personalizationString = personalizationString;
				this.securityStrength = securityStrength;
				this.primaryAdditionalInput = primaryAdditionalInput;
			}

			public IDrbg Get(IEntropySource entropySource)
			{
				HMacSP800Drbg drbg = new HMacSP800Drbg(hMac, securityStrength, entropySource, personalizationString, nonce);

				return new ContinuousTestingPseudoRng(drbg, primaryAdditionalInput);
			}
		}

		private class CTRDRBGProvider: IDrbgProvider
		{
			private readonly Org.BouncyCastle.Crypto.Internal.IBlockCipher blockCipher;
			private readonly int keySizeInBits;
			private readonly byte[] nonce;
			private readonly byte[] personalizationString;
			private readonly int securityStrength;
			private readonly byte[] primaryAdditionalInput;

			public CTRDRBGProvider(Org.BouncyCastle.Crypto.Internal.IBlockCipher blockCipher, int keySizeInBits, byte[] nonce, byte[] personalizationString, int securityStrength, byte[] primaryAdditionalInput)
			{
				CryptoStatus.IsReady();
				this.blockCipher = blockCipher;
				this.keySizeInBits = keySizeInBits;
				this.nonce = nonce;
				this.personalizationString = personalizationString;
				this.securityStrength = securityStrength;
				this.primaryAdditionalInput = primaryAdditionalInput;
			}

			public IDrbg Get(IEntropySource entropySource)
			{
				CtrSP800Drbg drbg = new CtrSP800Drbg(blockCipher, keySizeInBits, securityStrength, entropySource, personalizationString, nonce);

				return new ContinuousTestingPseudoRng(drbg, primaryAdditionalInput);
			}
		}

		private static void DrbgStartUpTest()
		{
			SelfTestExecutor.Validate(
				Sha1.Algorithm, new DRBGHashSelfTest(Sha1.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha1),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						128,
						new byte[][]
						{
							FipsKats.Values[FipsKats.Vec.DrbgSha1_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha1_B]
						})
					.setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha224.Algorithm, new DRBGHashSelfTest(Sha224.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha224),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						192,
						new byte[][]
						{
                            FipsKats.Values[FipsKats.Vec.DrbgSha224_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha224_B]
						})
					.setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha256.Algorithm, new DRBGHashSelfTest(Sha256.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha256),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
						new byte[][]
						{
                            FipsKats.Values[FipsKats.Vec.DrbgSha256_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha256_B]
						})
					.setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha384.Algorithm, new DRBGHashSelfTest(Sha384.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha384),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgSha384_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha384_B]
                        })
					.setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha512.Algorithm, new DRBGHashSelfTest(Sha512.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha512),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgSha512_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha512_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha512_224.Algorithm, new DRBGHashSelfTest(Sha512_224.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha512_224),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						192,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgSha512_224_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha512_224_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha512_256.Algorithm, new DRBGHashSelfTest(Sha512_256.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha512_256),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgSha512_256_A],
                            FipsKats.Values[FipsKats.Vec.DrbgSha512_256_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha1HMac.Algorithm, new DRBGHMACSelfTest(Sha1HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha1),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						128,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha1_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha1_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha224HMac.Algorithm, new DRBGHMACSelfTest(Sha224HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha224),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						192,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha224_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha224_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha256HMac.Algorithm, new DRBGHMACSelfTest(Sha256HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha256),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha256_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha256_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha384HMac.Algorithm, new DRBGHMACSelfTest(Sha384HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha384),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha384_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha384_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha512HMac.Algorithm, new DRBGHMACSelfTest(Sha512HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha512),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha512_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha512_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha512_224HMac.Algorithm, new DRBGHMACSelfTest(Sha512_224HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha512_224),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						192,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha512_224_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha512_224_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				Sha512_256HMac.Algorithm, new DRBGHMACSelfTest(Sha512_256HMac.Algorithm,
					new DRBGTestVector(
						FipsShs.CreateDigest(FipsShs.Sha512_256),
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha512_256_A],
                            FipsKats.Values[FipsKats.Vec.DrbgHMacSha512_256_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
		   SelfTestExecutor.Validate(
				CtrTripleDes168.Algorithm, new DRBGCTRSelfTest(CtrTripleDes168.Algorithm,
					new DRBGTestVector(
						FipsTripleDes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL),
						168,
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						112,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgCtrTripleDes168_A],
                            FipsKats.Values[FipsKats.Vec.DrbgCtrTripleDes168_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				CtrAes128.Algorithm, new DRBGCTRSelfTest(CtrAes128.Algorithm,
					new DRBGTestVector(
						FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL),
						128,
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						128,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgCtrAes128_A],
                            FipsKats.Values[FipsKats.Vec.DrbgCtrAes128_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
			SelfTestExecutor.Validate(
				CtrAes192.Algorithm, new DRBGCTRSelfTest(CtrAes192.Algorithm,
					new DRBGTestVector(
						FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL),
						192,
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						192,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgCtrAes192_A],
                            FipsKats.Values[FipsKats.Vec.DrbgCtrAes192_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
	     	SelfTestExecutor.Validate(
				CtrAes256.Algorithm, new DRBGCTRSelfTest(CtrAes256.Algorithm,
					new DRBGTestVector(
						FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL),
						256,
						new KatEntropyProvider().Get(440),
						true,
						"2021222324",
						256,
                        new byte[][]
                        {
                            FipsKats.Values[FipsKats.Vec.DrbgCtrAes256_A],
                            FipsKats.Values[FipsKats.Vec.DrbgCtrAes256_B]
                        })
                    .setPersonalizationString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F70717273747576")));
		}

		private abstract class DRBGSelfTest: VariantInternalKatTest
		{
			protected DRBGSelfTest(FipsAlgorithm algorithm): base(algorithm)
			{
			}
		}

		private class DRBGHashSelfTest: DRBGSelfTest
		{
			private readonly DRBGTestVector tv;

			internal DRBGHashSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv): base(algorithm)
			{
				this.tv = tv;
			}
				
			internal override void Evaluate()
			{
				byte[] nonce = tv.nonce();
				byte[] personalisationString = tv.personalizationString();

				ISP80090Drbg d = new HashSP800Drbg(tv.getDigest(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

				byte[] output = new byte[tv.expectedValue(0).Length];

				d.Generate(output, tv.additionalInput(0), tv.predictionResistance());

				byte[] expected = tv.expectedValue(0);

				if (!Arrays.AreEqual(expected, output))
				{
					Fail("Self test " + algorithm.Name + ".1 failed, expected " + Strings.FromByteArray(Hex.Encode(tv.expectedValue(0))) + " got " + Strings.FromByteArray(Hex.Encode(output)));
				}

				output = new byte[tv.expectedValue(0).Length];

				d.Generate(output, tv.additionalInput(1), tv.predictionResistance());

				expected = tv.expectedValue(1);
				if (!Arrays.AreEqual(expected, output))
				{
					Fail("Self test " + algorithm.Name + ".2 failed, expected " + Strings.FromByteArray(Hex.Encode(tv.expectedValue(1))) + " got " + Strings.FromByteArray(Hex.Encode(output)));
				}
			}
		}

		private class DRBGHMACSelfTest: DRBGSelfTest
		{
			private readonly DRBGTestVector tv;

			internal DRBGHMACSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv): base(algorithm)
			{
				this.tv = tv;
			}
				
			internal override void Evaluate()
			{
				byte[] nonce = tv.nonce();
				byte[] personalisationString = tv.personalizationString();

				ISP80090Drbg d = new HMacSP800Drbg(new HMac(tv.getDigest()), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

				byte[] output = new byte[tv.expectedValue(0).Length];

				d.Generate(output, tv.additionalInput(0), tv.predictionResistance());

				byte[] expected = tv.expectedValue(0);

				if (!Arrays.AreEqual(expected, output))
				{
					Fail("Self test " + algorithm.Name + ".1 failed, expected " + Strings.FromByteArray(Hex.Encode(tv.expectedValue(0))) + " got " + Strings.FromByteArray(Hex.Encode(output)));
				}

				output = new byte[tv.expectedValue(0).Length];

				d.Generate(output, tv.additionalInput(1), tv.predictionResistance());

				expected = tv.expectedValue(1);
				if (!Arrays.AreEqual(expected, output))
				{
					Fail("Self test " + algorithm.Name + ".2 failed, expected " + Strings.FromByteArray(Hex.Encode(tv.expectedValue(1))) + " got " + Strings.FromByteArray(Hex.Encode(output)));
				}
			}
		}

		private class DRBGCTRSelfTest: DRBGSelfTest
		{
			private readonly DRBGTestVector tv;

			internal DRBGCTRSelfTest(FipsAlgorithm algorithm, DRBGTestVector tv): base(algorithm)
			{
				this.tv = tv;
			}
				
			internal override void Evaluate()
			{
				byte[] nonce = tv.nonce();
				byte[] personalisationString = tv.personalizationString();

				ISP80090Drbg d = new CtrSP800Drbg(tv.getCipher(), tv.keySizeInBits(), tv.securityStrength(), tv.entropySource(), personalisationString, nonce);

				byte[] output = new byte[tv.expectedValue(0).Length];

				d.Generate(output, tv.additionalInput(0), tv.predictionResistance());

				byte[] expected = tv.expectedValue(0);

				if (!Arrays.AreEqual(expected, output))
				{
					Fail("Self test " + algorithm.Name + ".1 failed, expected " + Strings.FromByteArray(Hex.Encode(tv.expectedValue(0))) + " got " + Strings.FromByteArray(Hex.Encode(output)));
				}

				output = new byte[tv.expectedValue(0).Length];

				d.Generate(output, tv.additionalInput(1), tv.predictionResistance());

				expected = tv.expectedValue(1);
				if (!Arrays.AreEqual(expected, output))
				{
					Fail("Self test " + algorithm.Name + ".2 failed, expected " + Strings.FromByteArray(Hex.Encode(tv.expectedValue(1))) + " got " + Strings.FromByteArray(Hex.Encode(output)));
				}
			}
		}

		private class DRBGTestVector
		{
			private IDigest _digest;
			private Org.BouncyCastle.Crypto.Internal.IBlockCipher _cipher;
			private int _keySizeInBits;
			private IEntropySource _eSource;
			private bool _pr;
			private String _nonce;
			private String _personalisation;
			private int _ss;
			private byte[][] _ev;
			private List<string> _ai = new List<string>();

            public DRBGTestVector(IDigest digest, IEntropySource eSource, bool predictionResistance, String nonce, int securityStrength, byte[][] expected)
            {
                _digest = digest;
                _eSource = eSource;
                _pr = predictionResistance;
                _nonce = nonce;
                _ss = securityStrength;
                _ev = expected;
                _personalisation = null;
            }

			public DRBGTestVector(Org.BouncyCastle.Crypto.Internal.IBlockCipher cipher, int keySizeInBits, IEntropySource eSource, bool predictionResistance, String nonce, int securityStrength, byte[][] expected)
			{
				_cipher = cipher;
				_keySizeInBits = keySizeInBits;
				_eSource = eSource;
				_pr = predictionResistance;
				_nonce = nonce;
				_ss = securityStrength;
                _ev = expected;
                _personalisation = null;
			}

			public IDigest getDigest()
			{
				return _digest;
			}

			public Org.BouncyCastle.Crypto.Internal.IBlockCipher getCipher()
			{
				return _cipher;
			}

			public int keySizeInBits()
			{
				return _keySizeInBits;
			}

			public DRBGTestVector addAdditionalInput(String input)
			{
				_ai.Add(input);

				return this;
			}

			public DRBGTestVector setPersonalizationString(String p)
			{
				_personalisation = p;

				return this;
			}

			public IEntropySource entropySource()
			{
				return _eSource;
			}

			public bool predictionResistance()
			{
				return _pr;
			}

			public byte[] nonce()
			{
				if (_nonce == null)
				{
					return null;
				}

				return Hex.Decode(_nonce);
			}

			public byte[] personalizationString()
			{
				if (_personalisation == null)
				{
					return null;
				}

				return Hex.Decode(_personalisation);
			}

			public int securityStrength()
			{
				return _ss;
			}

			public byte[] expectedValue(int index)
			{
				return _ev[index];
			}

			public byte[] additionalInput(int position)
			{
				int len = _ai.Count;
				byte[] rv;
				if (position >= len)
				{
					rv = null;
				}
				else
				{
					rv = Hex.Decode((string)(_ai[position]));
				}
				return rv;
			}
		}

		private class KatEntropyProvider: DrbgKatFixedEntropySourceProvider
        {
			internal KatEntropyProvider(): base(
					Hex.Decode(
						"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536"
						+ "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6"
						+ "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6"), true)
			{
			}
		}
	}
}

