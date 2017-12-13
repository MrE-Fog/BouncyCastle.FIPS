using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for Poly1305 MAC calculators.
    /// </summary>
    public class Poly1305
    {
        /// <summary>
        /// Raw Poly1305 algorithm, can be used for creating general purpose Poly1305 keys.
        /// </summary>
        public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm("Poly1305");

        /// <summary>
        /// Parameters to use for creating a 256 bit Poly1305 key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen256 = new KeyGenerationParameters();

        /// <summary>
        /// Standard Poly1305 MAC mode.
        /// </summary>
        public static readonly AuthenticationParameters Mac = new AuthenticationParameters(Alg, 128);

        /// <summary>
        /// Base authentication parameters class for use the Poly1305 MAC.
        /// </summary>
        public class AuthenticationParameters
            : Algorithm, IAuthenticationParameters<AuthenticationParameters, Algorithm>
        {
            private readonly Algorithm algorithm;
            private readonly int macSizeInBits;

            internal AuthenticationParameters(Algorithm algorithm, int macSizeInBits)
                : base(algorithm.Name, algorithm.Mode)
            {
                this.algorithm = algorithm;
                this.macSizeInBits = macSizeInBits;
            }

            public Algorithm Algorithm
            {
                get { return this.algorithm; }
            }

            /// <summary>
            /// Return the size of the MAC these parameters are for.
            /// </summary>
            /// <value>The MAC size in bits.</value>
            public int MacSizeInBits
            {
                get { return macSizeInBits; }
            }

            /// <summary>
            /// Create a new parameter set with the specified MAC size associated with it.
            /// </summary>
            /// <returns>The new parameter set.</returns>
            /// <param name="macSizeInBits">Mac size in bits.</param>
            public AuthenticationParameters WithMacSize(int macSizeInBits)
            {
                return new AuthenticationParameters(this.algorithm, macSizeInBits);
            }
        }


        /// <summary>
        /// Poly1305 key class.
        /// </summary>
        public class Key
            : SymmetricSecretKey, ICryptoServiceType<IMacFactoryService>, IServiceProvider<IMacFactoryService>
        {
            public Key(byte[] keyBytes)
                : base(Alg, keyBytes)
            {
            }

            public Key(IParameters<Algorithm> parameterSet, byte[] bytes)
                : base(parameterSet, bytes)
            {
            }

            Func<IKey, IMacFactoryService> IServiceProvider<IMacFactoryService>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("service", this.Algorithm);

                return (key) => new Service(this);
            }
        }

        /// <summary>
        /// Poly1305 key generation parameters base class.
        /// </summary>
        public class KeyGenerationParameters
            : SymmetricKeyGenerationParameters<GeneralAlgorithm>, IGenerationServiceType<KeyGenerator>, IGenerationService<KeyGenerator>
        {
            internal KeyGenerationParameters()
                : base(Alg, 256)
            {
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyGenerator> IGenerationService<KeyGenerator>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("key generator", this.Algorithm);

                return (parameters, random) => new KeyGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Poly1305 key generator.
        /// </summary>
        public class KeyGenerator
            : ISymmetricKeyGenerator<Key>
        {
            private readonly Algorithm algorithm;
            private readonly int keySizeInBits;
            private readonly SecureRandom random;

            internal KeyGenerator(KeyGenerationParameters parameters, SecureRandom random)
                : this(Alg, parameters.KeySize, random)
            {
            }

            internal KeyGenerator(Parameters<Algorithm> parameterSet, int keySizeInBits, SecureRandom random)
                : this(parameterSet.Algorithm, keySizeInBits, random)
            {
            }

            private KeyGenerator(Algorithm algorithm, int keySizeInBits, SecureRandom random)
            {
                if (keySizeInBits != 256)
                    throw new ArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.Name);

                this.algorithm = algorithm;
                this.keySizeInBits = keySizeInBits;
                this.random = random;
            }

            /// <summary>
            /// Generate a key.
            /// </summary>
            /// <returns>A Poly1305 key.</returns>
            public Key GenerateKey()
            {
                Poly1305KeyGenerator cipherKeyGenerator = new Poly1305KeyGenerator();
                cipherKeyGenerator.Init(new Internal.KeyGenerationParameters(random, keySizeInBits));
                return new Key(cipherKeyGenerator.GenerateKey());
            }
        }

        internal class Service
            : IMacFactoryService
        {
            private readonly IEngineProvider<Internal.IMac> engineProvider;

            internal Service(Poly1305.Key key)
            {
                engineProvider = new EngineProvider(key);
            }

            public IMacFactory<A> CreateMacFactory<A>(A algorithmDetails)
                where A : IAuthenticationParameters<A, Algorithm>
            {
                return new MacFactory<A>(algorithmDetails, engineProvider, 16);
            }
        }

        private static void ValidateKeySize(byte[] keyBytes)
        {
            if (keyBytes.Length != 32)
                throw new ArgumentException("invalid key size: " + Alg.Name);
        }

        internal static readonly IEngineProvider<Internal.IMac> ENGINE_PROVIDER = new EngineProvider(null);

        private class EngineProvider
            : IEngineProvider<Internal.IMac>
        {
            private readonly KeyParameter keyParameter;

            internal EngineProvider(Key key)
            {
                if (key != null)
                {
                    this.keyParameter = new KeyParameter(key.GetKeyBytes());
                }
            }

            public Internal.IMac CreateEngine(EngineUsage usage)
            {
                Internal.IMac engine = SelfTestExecutor.Validate(Alg, new Internal.Macs.Poly1305(), new EngineSelfTest());
                if (keyParameter != null)
                {
                    engine.Init(keyParameter);
                }

                return engine;
            }
        }

        private class EngineSelfTest
            : VariantKatTest<Internal.Macs.Poly1305>
        {
            internal override void Evaluate(Internal.Macs.Poly1305 engine)
            {
                byte[] input = Hex.Decode("48656c6c6f20776f726c6421");
                byte[] keyMaterial = Hex.Decode(
                     "746869732069732033322d6279746520" +
                     "6b657920666f7220506f6c7931333035");
                byte[] output = Hex.Decode("a6f745008f81c916a20dcc74eef2b2f0");
                byte[] tmp = new byte[output.Length];

                KeyParameter key = new KeyParameter(keyMaterial);

                engine.Init(key);
               
                engine.BlockUpdate(input, 0, input.Length);

                engine.DoFinal(tmp, 0);

                if (!Arrays.AreEqual(output, tmp))
                {
                    Fail("failed self test on encoding");
                }
            }
        }
    }
}
