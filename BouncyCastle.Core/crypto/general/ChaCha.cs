
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using System;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.General
{
	public class ChaCha
	{
		public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm("ChaCha");

        public static readonly KeyGenerationParameters KeyGen128 = new KeyGenerationParameters(128);
        public static readonly KeyGenerationParameters KeyGen256 = new KeyGenerationParameters(256);

        /// <summary>
        /// ChaCha in eSTREAM mode, as described in the eSTREAM submission, with an 8 byte nonce.
        /// </summary>
        public static readonly Parameters EStream = new Parameters(8);

        /// <summary>
        /// ChaCha in IETF mode, as described in RFC 7539, with a 12 byte nonce.
        /// </summary>
        public static readonly Parameters Ietf = new Parameters(12);

        public class Parameters: ParametersWithIV<Parameters, Algorithm>
        {
            private readonly int rounds;
            private readonly int ivLength;

            internal Parameters(int ivLength): this(20, ivLength)
            {
            }

            Parameters(int rounds, int ivLength): this(rounds, ivLength, null)
            {
            }

            Parameters(int rounds, int ivLength, byte[] iv) : base(Alg, ivLength, iv)
            {
                this.rounds = rounds;
                this.ivLength = ivLength;
            }

            public Parameters WithRounds(int rounds)
            {
                return new Parameters(rounds, ivLength, GetIV());
            }

            public int Rounds
            {
                get
                {
                    return rounds;
                }
            }

            internal override Parameters CreateParameter(Algorithm algorithm, byte[] iv)
            {
                if (iv.Length != ivLength)
                {
                    throw new ArgumentException("IV must be " + (ivLength * 8) + " bits long");
                }

                return new Parameters(rounds, ivLength, iv);
            }
        }

        /// <summary>
        /// ChaCha key class.
        /// </summary>
        public class Key : SymmetricSecretKey, ICryptoServiceType<IStreamCipherService>, IServiceProvider<IStreamCipherService>
        {
            public Key(byte[] keyBytes) : base(Alg, keyBytes)
            {
            }

            public Key(IParameters<Algorithm> parameterSet, byte[] bytes) : base(parameterSet, bytes)
            {
            }

            Func<IKey, IStreamCipherService> IServiceProvider<IStreamCipherService>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("service", this.Algorithm);

                return (key) => new Service(this);
            }
        }

        /// <summary>
        /// ChaCha key generation parameters base class.
        /// </summary>
        public class KeyGenerationParameters : SymmetricKeyGenerationParameters<GeneralAlgorithm>, IGenerationServiceType<KeyGenerator>, IGenerationService<KeyGenerator>
        {
            internal KeyGenerationParameters(int sizeInBits): base(Alg, sizeInBits)
            {
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyGenerator> IGenerationService<KeyGenerator>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("key generator", this.Algorithm);

                return (parameters, random) => new KeyGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// ChaCha key generator.
        /// </summary>
        public class KeyGenerator : ISymmetricKeyGenerator<Key>
        {
            private readonly Algorithm algorithm;
            private readonly int keySizeInBits;
            private readonly SecureRandom random;

            internal KeyGenerator(KeyGenerationParameters parameters, SecureRandom random) : this(Alg, parameters.KeySize, random)
            {
            }

            internal KeyGenerator(Parameters parameterSet, int keySizeInBits, SecureRandom random) : this(parameterSet.Algorithm, keySizeInBits, random)
            {
            }

            private KeyGenerator(Algorithm algorithm, int keySizeInBits, SecureRandom random)
            {
                if (keySizeInBits != 128 && keySizeInBits != 256)
                {
                    throw new ArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.Name);
                }

                this.algorithm = algorithm;
                this.keySizeInBits = keySizeInBits;
                this.random = random;
            }

            /// <summary>
            /// Generate a key.
            /// </summary>
            /// <returns>A ChaCha key.</returns>
            public Key GenerateKey()
            {
                CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

                cipherKeyGenerator.Init(new Internal.KeyGenerationParameters(random, keySizeInBits));

                return new Key(cipherKeyGenerator.GenerateKey());
            }
        }
			
		private class Provider: IDecryptorBuilderProvider<Parameters>, IEncryptorBuilderProvider<Parameters>
        {
			private readonly IEngineProvider<Internal.IStreamCipher> engineProvider;

			public Provider(IEngineProvider<Internal.IStreamCipher> engineProvider)
			{
				this.engineProvider = engineProvider;
			}

            public ICipherBuilder<Parameters> CreateDecryptorBuilder(Parameters parameters)
            {
                return DoCreateCipherBuilder(false, parameters);
            }

            public ICipherBuilder<Parameters> CreateEncryptorBuilder(Parameters parameters)
            {
                return DoCreateCipherBuilder(true, parameters);
            }

            public ICipherBuilder<Parameters> DoCreateCipherBuilder(bool forEncryption, Parameters parameters)
			{
				IBufferedCipher cipher = new BufferedStreamCipher (engineProvider.CreateEngine (forEncryption ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION));

				cipher.Init (forEncryption, new ParametersWithRounds(new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()), parameters.Rounds));

				return new CipherBuilderImpl<Parameters> (parameters, cipher);
			}
        }

        internal class Service : IStreamCipherService
        {
            private readonly Provider prov;
   
            internal Service(ChaCha.Key key)
            {
                IEngineProvider<Internal.IStreamCipher> engineProvider = new EngineProvider(key);

                this.prov = new Provider(engineProvider);
            }

            public ICipherBuilder<A> CreateDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                return (ICipherBuilder<A>)prov.CreateDecryptorBuilder(algorithmDetails as Parameters);
            }

            public ICipherBuilder<A> CreateEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                return (ICipherBuilder<A>)prov.CreateEncryptorBuilder(algorithmDetails as Parameters);
            }
        }

        private static void validateKeySize(byte[] keyBytes)
        {
            int keyLen = keyBytes.Length;
            if (keyLen != 16 && keyLen != 32)
            {
                throw new ArgumentException("invalid key size: " + Alg.Name);
            }
        }

        internal static readonly IEngineProvider<Internal.IStreamCipher> ENGINE_PROVIDER = new EngineProvider(null);

        private class EngineProvider : IEngineProvider<Internal.IStreamCipher>
        {
            private readonly KeyParameter keyParameter;

            internal EngineProvider(Key key)
            {
                if (key != null)
                {
                    this.keyParameter = new KeyParameter(key.GetKeyBytes());
                }
            }

            public Internal.IStreamCipher CreateEngine(EngineUsage usage)
            {
                Internal.IStreamCipher engine = SelfTestExecutor.Validate(Alg, new ChaChaEngine(), new EngineSelfTest());
                if (keyParameter != null)
                {
                    engine.Init(usage == EngineUsage.ENCRYPTION, keyParameter);
                }

                return engine;
            }
        }

        private class EngineSelfTest : VariantKatTest<ChaChaEngine>
        {
            internal override void Evaluate(ChaChaEngine engine)
            {
                byte[] input = Hex.Decode("00112233445566778899aabbccddeeff");
                byte[] output = Hex.Decode("53a3dafb3aa135f7697cf3b8b01ddf56");
                byte[] tmp = new byte[input.Length];

                KeyParameter key = new KeyParameter(Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

                engine.Init(true, key);
                engine.Init(true, new ParametersWithIV(null, Hex.Decode("0D74DB42A91077DE")));

                engine.ProcessBytes(input, 0, input.Length, tmp, 0);

                if (!Arrays.AreEqual(output, tmp))
                {
                    Fail("failed self test on encryption");
                }

                engine.Init(false, key);
                engine.Init(false, new ParametersWithIV(null, Hex.Decode("0D74DB42A91077DE")));

                engine.ProcessBytes(tmp, 0, tmp.Length, tmp, 0);

                if (!Arrays.AreEqual(input, tmp))
                {
                    Fail("failed self test on decryption");
                }
            }
        }
    }
}

