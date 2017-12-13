
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
    /// <summary>
    /// Source class for ARC4/RC4 based algorithms.
    /// </summary>
    public class Arc4
	{
        /// <summary>
        /// Raw ARC4/RC4 algorithm, can be used for creating general purpose Camellia keys.
        /// </summary>
        public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm("ARC4");

        /// <summary>
        /// Parameters to use for creating an ARC4/RC4 key generator (default is 128 bits).
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen = new KeyGenerationParameters(128);

        /// <summary>
        /// Standard ARC4/RC4 stream mode.
        /// </summary>
        public static readonly Parameters Stream = new Parameters();

        /// <summary>
        /// ARC4/RC4 key class.
        /// </summary>
        public class Key : SymmetricSecretKey, ICryptoServiceType<IStreamCipherService>, IServiceProvider<IStreamCipherService>
        {
            public Key(byte[] keyBytes) : base(Alg, keyBytes)
            {
                validateKeySize(keyBytes.Length * 8);
            }

            public Key(IParameters<Algorithm> parameterSet, byte[] keyBytes) : base(parameterSet, keyBytes)
            {
                validateKeySize(keyBytes.Length * 8);
            }

            Func<IKey, IStreamCipherService> IServiceProvider<IStreamCipherService>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("service", this.Algorithm);

                return (key) => new Service(this);
            }
        }

        /// <summary>
        /// Base ARC4/RC4 key generation parameters.
        /// </summary>
        public class KeyGenerationParameters : SymmetricKeyGenerationParameters<GeneralAlgorithm>, IGenerationServiceType<KeyGenerator>, IGenerationService<KeyGenerator>
        {
            internal KeyGenerationParameters(int sizeInBits): base(Alg, sizeInBits)
            {
            }

            public KeyGenerationParameters WithKeySize(int sizeInBits)
            {
                validateKeySize(sizeInBits);

                return new KeyGenerationParameters(sizeInBits);
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyGenerator> IGenerationService<KeyGenerator>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("key generator", this.Algorithm);

                return (parameters, random) => new KeyGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// ARC4/RC4 key generator.
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
                this.algorithm = algorithm;
                this.keySizeInBits = keySizeInBits;
                this.random = random;
            }

            /// <summary>
            /// Generate a key.
            /// </summary>
            /// <returns>An ARC4 key.</returns>
            public Key GenerateKey()
            {
                CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

                cipherKeyGenerator.Init(new Internal.KeyGenerationParameters(random, keySizeInBits));

                return new Key(cipherKeyGenerator.GenerateKey());
            }
        }

        /// <summary>
        /// Base class for stanard ARC4/RC4 mode of operation.
        /// </summary>
        public class Parameters: Parameters<GeneralAlgorithm>
		{
			internal Parameters():base(Alg)
			{
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
                return doCreateCipherBuilder(false, parameters);
            }

            public ICipherBuilder<Parameters> CreateEncryptorBuilder(Parameters parameters)
            {
                return doCreateCipherBuilder(true, parameters);
            }

            public ICipherBuilder<Parameters> doCreateCipherBuilder(bool forEncryption, Parameters parameters)
			{
				IBufferedCipher cipher = new BufferedStreamCipher (engineProvider.CreateEngine (forEncryption ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION));

				cipher.Init (forEncryption, null);

				return new CipherBuilderImpl<Parameters> (parameters, cipher);
			}
        }

        internal class Service : IStreamCipherService
        {
            private readonly Provider prov;
   
            internal Service(Arc4.Key key)
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

        private static void validateKeySize(int keyLength)
        {
            if (keyLength < 40 || keyLength > 2048)
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
                Internal.IStreamCipher engine = SelfTestExecutor.Validate(Alg, new RC4Engine(), new EngineSelfTest());
                if (keyParameter != null)
                {
                    engine.Init(usage == EngineUsage.ENCRYPTION, keyParameter);
                }

                return engine;
            }
        }

        private class EngineSelfTest : VariantKatTest<RC4Engine>
        {
            internal override void Evaluate(RC4Engine engine)
            {
                byte[] input = Hex.Decode("00112233445566778899aabbccddeeff");
                byte[] output = Hex.Decode("1035d3faeefacf4afea5343bc4e8876c");
                byte[] tmp = new byte[input.Length];

                KeyParameter key = new KeyParameter(Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

                engine.Init(true, key);

                engine.ProcessBytes(input, 0, input.Length, tmp, 0);

                if (!Arrays.AreEqual(output, tmp))
                {
                    Fail("failed self test on encryption");
                }

                engine.Init(false, key);

                engine.ProcessBytes(tmp, 0, tmp.Length, tmp, 0);

                if (!Arrays.AreEqual(input, tmp))
                {
                    Fail("failed self test on decryption");
                }
            }
        }
    }
}

