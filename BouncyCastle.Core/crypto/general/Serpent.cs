using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for Serpent based algorithms.
    /// </summary>
    public class Serpent
    {
        /// <summary>
        /// Raw Serpent algorithm, can be used for creating general purpose Serpent keys.
        /// </summary>
        public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm("Serpent");

        /// <summary>
        /// Algorithm tag for Serpent with 128 bit key.
        /// </summary>
        public static readonly GeneralAlgorithm Alg128 = new GeneralAlgorithm("Serpent");

        /// <summary>
        /// Algorithm tag for Serpent with 192 bit key.
        /// </summary>
        public static readonly GeneralAlgorithm Alg192 = new GeneralAlgorithm("Serpent");

        /// <summary>
        /// Algorithm tag for Serpent with 256 bit key.
        /// </summary>
        public static readonly GeneralAlgorithm Alg256 = new GeneralAlgorithm("Serpent");

        /// <summary>
        /// Parameters to use for creating a 128 bit Serpent key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen128 = new KeyGenerationParameters(128);

        /// <summary>
        /// Parameters to use for creating a 192 bit Serpent key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen192 = new KeyGenerationParameters(192);

        /// <summary>
        /// Parameters to use for creating a 256 bit Serpent key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen256 = new KeyGenerationParameters(256);

        /// <summary>
        /// Serpent in electronic code book (ECB) mode.
        /// </summary>
        public static readonly Parameters Ecb = new Parameters(new GeneralAlgorithm(Alg, AlgorithmMode.ECB));

        /// <summary>
        /// Serpent in cipher block chaining (CBC) mode.
        /// </summary>
        public static readonly ParametersWithIV Cbc = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CBC));

        /// <summary>
        ///  Serpent in cipher feedback (CFB) mode, 8 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Cfb8 = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CFB8));

        /// <summary>
        /// Serpent in cipher feedback (CFB) mode, 128 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Cfb128 = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CFB128));

        /// <summary>
        /// Serpent in output feedback (OFB) mode - 128 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Ofb = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.OFB128));

        /// <summary>
        ///  Serpent in counter (CTR) mode.
        /// </summary>
        public static readonly ParametersWithIV Ctr = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CTR));

        /// <summary>
        ///  Serpent in CBC mode with cipher text stealing type CS1.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS1 = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CS1));

        /// <summary>
        ///  Serpent in CBC mode with cipher text stealing type CS2.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS2 = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CS2));

        /// <summary>
        ///  Serpent in CBC mode with cipher text stealing type CS3.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS3 = new ParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CS3));

        /// <summary>
        ///  Serpent in counter with CBC-MAC (CCM).
        /// </summary>
        public static readonly AuthenticationParametersWithIV Ccm = new AuthenticationParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.CCM), 64);

        /// <summary>
        /// Serpent in Galois/Counter Mode (GCM).
        /// </summary>
        public static readonly AuthenticationParametersWithIV Gcm = new AuthenticationParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.GCM), 128);

        /// <summary>
        /// Serpent cipher-based CMAC algorithm.
        /// </summary>
        public static readonly AuthenticationParameters CMac = new AuthenticationParameters(new GeneralAlgorithm(Alg, AlgorithmMode.CMAC), 128);

        /// <summary>
        /// Serpent cipher-based GMAC algorithm.
        /// </summary>
        public static readonly AuthenticationParametersWithIV GMac = new AuthenticationParametersWithIV(new GeneralAlgorithm(Alg, AlgorithmMode.GMAC), 128);

        /// <summary>
        /// Serpent as a General SP800-38F key wrapper.
        /// </summary>
        public static readonly WrapParameters KW = new WrapParameters(new GeneralAlgorithm(Alg, AlgorithmMode.WRAP));

        /// <summary>
        /// Serpent as a General SP800-38F key wrapper with padding.
        /// </summary>
        public static readonly WrapParameters KWP = new WrapParameters(new GeneralAlgorithm(Alg, AlgorithmMode.WRAPPAD));

        /// <summary>
        /// Serpent key class.
        /// </summary>
        public class Key : SymmetricSecretKey, ICryptoServiceType<IAeadBlockCipherService>, IServiceProvider<IAeadBlockCipherService>
        {
            public Key(byte[] keyBytes) : base(Serpent.Alg, keyBytes)
            {
            }

            public Key(IParameters<Algorithm> parameterSet, byte[] bytes) : base(parameterSet, bytes)
            {
            }

            public Key(Algorithm algorithm, byte[] bytes) : base(algorithm, bytes)
            {
                if (algorithm == Alg128 && bytes.Length != 16)
                {
                    throw new ArgumentException("Key must be 128 bits long");
                }
                else if (algorithm == Alg192 && bytes.Length != 24)
                {
                    throw new ArgumentException("Key must be 192 bits long");
                }
                else if (algorithm == Alg256 && bytes.Length != 32)
                {
                    throw new ArgumentException("Key must be 256 bits long");
                }
                else
                {
                    validateKeySize(bytes);
                }
            }

            Func<IKey, IAeadBlockCipherService> IServiceProvider<IAeadBlockCipherService>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("service", this.Algorithm);

                return (key) => new Serpent.Service(new EngineProvider(this));
            }
        }

        /// <summary>
        /// Serpent key generation parameters base class.
        /// </summary>
        public class KeyGenerationParameters : SymmetricKeyGenerationParameters<Algorithm>, IGenerationServiceType<KeyGenerator>, IGenerationService<KeyGenerator>
        {
            internal KeyGenerationParameters(int sizeInBits) : base(Alg, sizeInBits)
            {
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyGenerator> IGenerationService<KeyGenerator>.GetFunc(SecurityContext context)
            {
                Utils.ApprovedModeCheck("key generator", this.Algorithm);

                return (parameters, random) => new KeyGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Serpent key generator.
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
            /// <returns>A Serpent key.</returns>
            public Key GenerateKey()
            {
                CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

                cipherKeyGenerator.Init(new Internal.KeyGenerationParameters(random, keySizeInBits));

                return new Key(cipherKeyGenerator.GenerateKey());
            }
        }

        /// <summary>
        /// Base class for simple Serpent parameters.
        /// </summary>
        public class Parameters : Parameters<GeneralAlgorithm>
        {
            internal Parameters(GeneralAlgorithm algorithm) : base(algorithm)
            {
            }
        }

        /// <summary>
        /// Base class for Serpent parameters requiring an initialization vector.
        /// </summary>
        public class ParametersWithIV : ParametersWithIV<ParametersWithIV, GeneralAlgorithm>
        {
            internal ParametersWithIV(GeneralAlgorithm algorithm) : this(algorithm, null)
            {
            }

            private ParametersWithIV(GeneralAlgorithm algorithm, byte[] iv) : base(algorithm, 16, iv)
            {
            }

            internal override ParametersWithIV CreateParameter(GeneralAlgorithm algorithm, byte[] iv)
            {
                return new ParametersWithIV(algorithm, iv);
            }
        }

        /// <summary>
        /// Base authentication parameters class for use with MACs.
        /// </summary>
        public class AuthenticationParameters : AuthenticationParameters<AuthenticationParameters, GeneralAlgorithm>
        {
            internal AuthenticationParameters(GeneralAlgorithm algorithm, int macSize) : base(algorithm, macSize)
            {
            }

            internal override AuthenticationParameters CreateParameter(GeneralAlgorithm algorithm, int macSize)
            {
                return new AuthenticationParameters(algorithm, macSize);
            }
        }

        /// <summary>
        /// Base authentication parameters class for use with MACs and AEAD ciphers requiring a nonce or IV.
        /// </summary>
        public class AuthenticationParametersWithIV : AuthenticationParametersWithIV<AuthenticationParametersWithIV, GeneralAlgorithm>
        {
            internal AuthenticationParametersWithIV(GeneralAlgorithm algorithm, int macSize) : this(algorithm, macSize, null)
            {
            }

            private AuthenticationParametersWithIV(GeneralAlgorithm algorithm, int macSize, byte[] iv) : base(algorithm, macSize, 16, iv)
            {
            }

            internal override AuthenticationParametersWithIV CreateParameter(GeneralAlgorithm algorithm, int macSize, byte[] iv)
            {
                return new AuthenticationParametersWithIV(algorithm, macSize, iv);
            }
        }

        /// <summary>
        /// Base class for Serpent key wrap parameters.
        /// </summary>
        public class WrapParameters : SymmetricWrapParameters<WrapParameters, GeneralAlgorithm>
        {
            internal WrapParameters(GeneralAlgorithm algorithm) : this(algorithm, false, null)
            {
            }

            private WrapParameters(GeneralAlgorithm algorithm, bool useInverse, byte[] iv) : base(algorithm, useInverse, iv)
            {
            }

            internal override WrapParameters CreateParameter(GeneralAlgorithm algorithm, bool useInverse, byte[] iv)
            {
                return new WrapParameters(algorithm, useInverse, iv);
            }
        }

        internal class ProviderForIV : GeneralIVBlockCipherProvider<ParametersWithIV, AuthenticationParametersWithIV>
        {
            public ProviderForIV(String name, IEngineProvider<Internal.IBlockCipher> engineProvider) : base(name, engineProvider)
            {
            }
        }

        internal class Provider : GeneralBlockCipherProvider<Parameters, WrapParameters, AuthenticationParameters>
        {
            public Provider(String name, IEngineProvider<Internal.IBlockCipher> engineProvider) : base(name, engineProvider)
            {
            }
        }

        internal class Service : GeneralBlockCipherService<Provider, ProviderForIV>
        {
            internal Service(IEngineProvider<Internal.IBlockCipher> engineProvider) : base(new Provider("Serpent", engineProvider), new ProviderForIV("Serpent", engineProvider))
            {
            }
        }

        private static void validateKeySize(byte[] keyBytes)
        {
            int keyLen = keyBytes.Length;
            if (keyLen != 16 && keyLen != 24 && keyLen != 32)
            {
                throw new ArgumentException("invalid key size: " + Alg.Name);
            }
        }

        internal static readonly IEngineProvider<Internal.IBlockCipher> ENGINE_PROVIDER = new EngineProvider(null);

        private class EngineProvider : IEngineProvider<Internal.IBlockCipher>
        {
            private readonly KeyParameter keyParameter;

            internal EngineProvider(Key key)
            {
                if (key != null)
                {
                    this.keyParameter = new KeyParameter(key.GetKeyBytes());
                }
            }

            public Internal.IBlockCipher CreateEngine(EngineUsage usage)
            {
                Internal.IBlockCipher engine = SelfTestExecutor.Validate(Alg, new SerpentEngine(), new EngineSelfTest());
                if (keyParameter != null)
                {
                    engine.Init(usage == EngineUsage.ENCRYPTION, keyParameter);
                }

                return engine;
            }
        }

        private class EngineSelfTest : VariantKatTest<SerpentEngine>
        {
            internal override void Evaluate(SerpentEngine engine)
            {
                byte[] input = Hex.Decode("3DA46FFA6F4D6F30CD258333E5A61369");
                byte[] output = Hex.Decode("00112233445566778899AABBCCDDEEFF");
                byte[] tmp = new byte[input.Length];

                KeyParameter key = new KeyParameter(Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

                engine.Init(true, key);

                engine.ProcessBlock(input, 0, tmp, 0);

                if (!Arrays.AreEqual(output, tmp))
                {
                    Fail("failed self test on encryption");
                }

                engine.Init(false, key);

                engine.ProcessBlock(tmp, 0, tmp, 0);

                if (!Arrays.AreEqual(input, tmp))
                {
                    Fail("failed self test on decryption");
                }
            }
        }
    }
}