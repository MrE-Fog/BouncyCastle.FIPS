using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Internal.Modes;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved implementations of AES based algorithms.
    /// </summary>
    public class FipsAes
    {
        /// <summary>
        /// Raw AES algorithm, can be used for creating general purpose AES keys.
        /// </summary>
        public static readonly FipsAlgorithm Alg = new FipsAlgorithm("AES");

        /// <summary>
        /// Algorithm tag for AES with 128 bit key.
        /// </summary>
        public static readonly FipsAlgorithm Alg128 = new FipsAlgorithm("AES");

        /// <summary>
        /// Algorithm tag for AES with 192 bit key.
        /// </summary>
        public static readonly FipsAlgorithm Alg192 = new FipsAlgorithm("AES");

        /// <summary>
        /// Algorithm tag for AES with 256 bit key.
        /// </summary>
        public static readonly FipsAlgorithm Alg256 = new FipsAlgorithm("AES");

        /// <summary>
        /// Parameters to use for creating a 128 bit AES key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen128 = new KeyGenerationParameters(128);

        /// <summary>
        /// Parameters to use for creating a 192 bit AES key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen192 = new KeyGenerationParameters(192);

        /// <summary>
        /// Parameters to use for creating a 256 bit AES key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen256 = new KeyGenerationParameters(256);

        /// <summary>
        /// AES in electronic code book (ECB) mode.
        /// </summary>
        public static readonly Parameters Ecb = new Parameters(new FipsAlgorithm(Alg, AlgorithmMode.ECB));

        /// <summary>
        /// AES in cipher block chaining (CBC) mode.
        /// </summary>
        public static readonly ParametersWithIV Cbc = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CBC));

        /// <summary>
        ///  AES in cipher feedback (CFB) mode, 8 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Cfb8 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CFB8));

        /// <summary>
        /// AES in cipher feedback (CFB) mode, 128 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Cfb128 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CFB128));

        /// <summary>
        /// AES in output feedback (OFB) mode - 128 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Ofb = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.OFB128));
        
        /// <summary>
        ///  AES in counter (CTR) mode.
        /// </summary>
        public static readonly ParametersWithIV Ctr = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CTR));

        /// <summary>
        ///  AES in CBC mode with cipher text stealing type CS1.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS1 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CS1));

        /// <summary>
        ///  AES in CBC mode with cipher text stealing type CS2.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS2 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CS2));

        /// <summary>
        ///  AES in CBC mode with cipher text stealing type CS3.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS3 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CS3));

        /// <summary>
        ///  AES in counter with CBC-MAC (CCM).
        /// </summary>
        public static readonly AuthenticationParametersWithIV Ccm = new AuthenticationParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CCM), 64);

        /// <summary>
        /// AES in Galois/Counter Mode (GCM).
        /// </summary>
        public static readonly AuthenticationParametersWithIV Gcm = new AuthenticationParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.GCM), 128);

        /// <summary>
        /// AES cipher-based CMAC algorithm.
        /// </summary>
        public static readonly AuthenticationParameters CMac = new AuthenticationParameters(new FipsAlgorithm(Alg, AlgorithmMode.CMAC), 128);

        /// <summary>
        /// AES cipher-based GMAC algorithm.
        /// </summary>
        public static readonly AuthenticationParametersWithIV GMac = new AuthenticationParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.GMAC), 128);

        /// <summary>
        /// AES as a FIPS SP800-38F/RFC 3394 key wrapper.
        /// </summary>
        public static readonly WrapParameters KW = new WrapParameters(new FipsAlgorithm(Alg, AlgorithmMode.WRAP));

        /// <summary>
        /// AES as a FIPS SP800-38F key wrapper with padding.
        /// </summary>
        public static readonly WrapParameters KWP = new WrapParameters(new FipsAlgorithm(Alg, AlgorithmMode.WRAPPAD));

        static FipsAes()
        {
            EngineProvider provider = new EngineProvider(null);

            // FSM_STATE:3.AES.0,"AES ENCRYPT DECRYPT KAT", "The module is performing AES encrypt and decrypt KAT self-test"
            // FSM_TRANS:3.AES.0,"POWER ON SELF-TEST", "AES ENCRYPT DECRYPT KAT", "Invoke AES Encrypt/Decrypt KAT self-test"
            provider.CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.AES.1,"AES ENCRYPT DECRYPT KAT", "POWER ON SELF-TEST", "AES Encrypt / Decrypt KAT self-test successful completion"

            // FSM_STATE:3.AES.1,"CCM GENERATE VERIFY KAT", "The module is performing AES CCM generate and verify KAT self-test"
            // FSM_TRANS:3.AES.2,"POWER ON SELF-TEST", "CCM GENERATE VERIFY KAT",	"Invoke CCM Generate/Verify KAT self-test"
            CcmStartUpTest(provider);
            // FSM_TRANS:3.AES.3, "CCM GENERATE VERIFY KAT", "POWER ON SELF-TEST", "CCM Generate/Verify KAT self-test successful completion"

            // FSM_STATE:3.AES.2,"AES-CMAC GENERATE VERIFY KAT", "The module is performing AES-CMAC generate and verify KAT self-test"
            // FSM_TRANS:3.AES.4, "POWER ON SELF-TEST", "AES-CMAC GENERATE VERIFY KAT", "Invoke CMAC Generate/Verify KAT self-test"
            CMacStartUpTest(provider);
            // FSM_TRANS:3.AES.5, "AES-CMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST", "CMAC Generate/Verify KAT self-test successful completion"

            // FSM_STATE:3.AES.3,"GCM GMAC GENERATE VERIFY KAT", "The module is performing GCM/GMAC generate and verify KAT self-test"
            // FSM_TRANS:3.AES.6,"POWER ON SELF-TEST", "GCM GMAC GENERATE VERIFY KAT",	"Invoke GCM Generate/Verify KAT self-test"
            GcmStartUpTest(provider);
            // FSM_TRANS:3.AES.7, "GCM GMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST", "GCM Generate/Verify KAT self-test successful completion"

            ENGINE_PROVIDER = provider;
        }

        /// <summary>
        /// AES key class.
        /// </summary>
        public class Key
            : SymmetricSecretKey, ICryptoServiceType<IAeadBlockCipherService>, IServiceProvider<IAeadBlockCipherService>
        {
            public Key(byte[] keyBytes)
                : base(FipsAes.Alg, keyBytes)
            {
                ValidateKeySize(keyBytes);
            }

            public Key(FipsAlgorithm algorithm, byte[] bytes)
                : base(algorithm, bytes)
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
                    ValidateKeySize(bytes);
                }
            }

            public Key(IParameters<FipsAlgorithm> parameterSet, byte[] bytes)
                : base(parameterSet, bytes)
            {
                ValidateKeySize(bytes);
            }

            Func<IKey, IAeadBlockCipherService> IServiceProvider<IAeadBlockCipherService>.GetFunc(SecurityContext context)
            {
                return (key) => new Service(this);
            }
        }

        /// <summary>
        /// AES key generation parameters base class.
        /// </summary>
        public class KeyGenerationParameters
            : SymmetricKeyGenerationParameters<FipsAlgorithm>, IGenerationServiceType<KeyGenerator>, IGenerationService<KeyGenerator>
        {
            internal KeyGenerationParameters(int sizeInBits)
                : base(Alg, sizeInBits)
            {
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyGenerator> IGenerationService<KeyGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// AES key generator.
        /// </summary>
        public class KeyGenerator
            : ISymmetricKeyGenerator<Key>
        {
            private readonly FipsAlgorithm algorithm;
            private readonly int keySizeInBits;
            private readonly SecureRandom random;

            internal KeyGenerator(KeyGenerationParameters parameters, SecureRandom random)
                : this(Alg, parameters.KeySize, random)
            {
            }

            internal KeyGenerator(FipsParameters parameterSet, int keySizeInBits, SecureRandom random)
                : this(parameterSet.Algorithm, keySizeInBits, random)
            {
            }

            private KeyGenerator(FipsAlgorithm algorithm, int keySizeInBits, SecureRandom random)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    Utils.ValidateKeyGenRandom(random, keySizeInBits, algorithm);
                }

                this.algorithm = algorithm;
                this.keySizeInBits = keySizeInBits;
                this.random = random;
            }

            /// <summary>
            /// Generate a key.
            /// </summary>
            /// <returns>An AES key.</returns>
            public FipsAes.Key GenerateKey()
            {
                CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();
                cipherKeyGenerator.Init(new Internal.KeyGenerationParameters(random, keySizeInBits));
                return new Key(cipherKeyGenerator.GenerateKey());
            }
        }

        /// <summary>
        /// Base class for simple AES parameters.
        /// </summary>
        public class Parameters
            : Parameters<FipsAlgorithm>
        {
            internal Parameters(FipsAlgorithm algorithm)
                : base(algorithm)
            {
            }
        }

        /// <summary>
        /// Base class for AES parameters requiring an initialization vector.
        /// </summary>
        public class ParametersWithIV
            : ParametersWithIV<ParametersWithIV, FipsAlgorithm>
        {
            internal ParametersWithIV(FipsAlgorithm algorithm)
                : this(algorithm, null)
            {
            }

            private ParametersWithIV(FipsAlgorithm algorithm, byte[] iv)
                : base(algorithm, 16, iv)
            {
            }

            internal override ParametersWithIV CreateParameter(FipsAlgorithm algorithm, byte[] iv)
            {
                return new ParametersWithIV(algorithm, iv);
            }
        }

        /// <summary>
        /// Base authentication parameters class for use with MACs.
        /// </summary>
        public class AuthenticationParameters
            : AuthenticationParameters<AuthenticationParameters, FipsAlgorithm>
        {
            internal AuthenticationParameters(FipsAlgorithm algorithm, int macSize)
                : base(algorithm, macSize)
            {
            }

            internal override AuthenticationParameters CreateParameter(FipsAlgorithm algorithm, int macSize)
            {
                return new AuthenticationParameters(algorithm, macSize);
            }
        }

        /// <summary>
        /// Base authentication parameters class for use with MACs and AEAD ciphers requiring a nonce or IV.
        /// </summary>
        public class AuthenticationParametersWithIV
            : AuthenticationParametersWithIV<AuthenticationParametersWithIV, FipsAlgorithm>
        {
            internal AuthenticationParametersWithIV(FipsAlgorithm algorithm, int macSize)
                : this(algorithm, macSize, null)
            {
            }

            private AuthenticationParametersWithIV(FipsAlgorithm algorithm, int macSize, byte[] iv)
                : base(algorithm, macSize, 16, iv)
            {
            }

            /// <summary>
            /// Create a new parameter set with a different IV based on the output
            /// of the passed in random.
            /// </summary>
            /// <returns>A copy of the current parameter set with the new IV.</returns>
            /// <param name="random">A SecureRandom for deriving the IV.</param>
            public override AuthenticationParametersWithIV WithIV(SecureRandom random)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    if (Algorithm.Equals(Gcm.Algorithm))
                    {
                        Utils.ValidateRandom(random, "GCM IV can only be generated by an approved DRBG");
                    }
                }
                return new AuthenticationParametersWithIV(this.Algorithm, this.MacSizeInBits, CreateDefaultIvIfNecessary(16, random));
            }

            /// <summary>
            /// Create a new parameter set with a different IV based on the output
            /// of the passed in random.
            /// </summary>
            /// <returns>A copy of the current parameter set with the new IV.</returns>
            /// <param name="random">A SecureRandom for deriving the IV.</param>
            /// <param name="ivLen">Length of the IV to generate.</param>
            public override AuthenticationParametersWithIV WithIV(SecureRandom random, int ivLen)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    if (Algorithm.Equals(Gcm.Algorithm))
                    {
                        Utils.ValidateRandom(random, "GCM IV can only be generated by an approved DRBG");
                    }
                    if (ivLen < 12)
                    {
                        throw new CryptoUnapprovedOperationError("GCM IV must be at least 96 bits", Gcm.Algorithm);
                    }
                }
                return new AuthenticationParametersWithIV(this.Algorithm, this.MacSizeInBits, CreateDefaultIvIfNecessary(ivLen, random));
            }

            internal override AuthenticationParametersWithIV CreateParameter(FipsAlgorithm algorithm, int macSize, byte[] iv)
            {
                return new AuthenticationParametersWithIV(algorithm, macSize, iv);
            }
        }

        /// <summary>
        /// Base class for AES key wrap parameters.
        /// </summary>
        public class WrapParameters
            : SymmetricWrapParameters<WrapParameters, FipsAlgorithm>
        {
            internal WrapParameters(FipsAlgorithm algorithm)
                : this(algorithm, false, null)
            {
            }

            private WrapParameters(FipsAlgorithm algorithm, bool useInverse, byte[] iv)
                : base(algorithm, useInverse, iv)
            {
            }

            internal override WrapParameters CreateParameter(FipsAlgorithm algorithm, bool useInverse, byte[] iv)
            {
                return new WrapParameters(algorithm, useInverse, iv);
            }
        }

        internal class Provider : IBlockEncryptorBuilderProvider<Parameters>, IBlockEncryptorBuilderProvider<ParametersWithIV>, IEncryptorBuilderProvider<ParametersWithIV>,
            IBlockDecryptorBuilderProvider<Parameters>, IBlockDecryptorBuilderProvider<ParametersWithIV>, IDecryptorBuilderProvider<ParametersWithIV>,
            IAeadDecryptorBuilderProvider<AuthenticationParametersWithIV>, IAeadEncryptorBuilderProvider<AuthenticationParametersWithIV>,
            IKeyWrapperProvider<WrapParameters>, IKeyUnwrapperProvider<WrapParameters>,
            IMacFactoryProvider<AuthenticationParameters>, IMacFactoryProvider<AuthenticationParametersWithIV>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> aesEngineProvider;

            public Provider(String name, IEngineProvider<Internal.IBlockCipher> engine)
            {
                this.aesEngineProvider = engine;
            }

            public IKeyWrapper<WrapParameters> CreateKeyWrapper(WrapParameters parameters)
            {
                return new KeyWrapperImpl<WrapParameters>(parameters, DoCreateWrapper(true, parameters));
            }

            public IKeyUnwrapper<WrapParameters> CreateKeyUnwrapper(WrapParameters parameters)
            {
                return new KeyUnwrapperImpl<WrapParameters>(parameters, DoCreateWrapper(false, parameters));
            }

            private IWrapper DoCreateWrapper(bool forWrapping, WrapParameters parameters)
            {
                return ProviderUtils.CreateWrapper("FipsAES", parameters.Algorithm.Mode, parameters.IsUsingInverseFunction, forWrapping, aesEngineProvider);
            }

            public ICipherBuilder<ParametersWithIV> CreateDecryptorBuilder(ParametersWithIV parameters)
            {
                return DoCreateCipherBuilder(false, parameters);
            }

            public ICipherBuilder<ParametersWithIV> CreateEncryptorBuilder(ParametersWithIV parameters)
            {
                return DoCreateCipherBuilder(true, parameters);
            }

            private ICipherBuilder<ParametersWithIV> DoCreateCipherBuilder(bool forEncryption, ParametersWithIV parameters)
            {
                IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher("FipsAES", parameters.Algorithm.Mode, parameters, forEncryption, aesEngineProvider);
                cipher.Init(forEncryption, Internal.Parameters.ParametersWithIV.ApplyOptionalIV(null, parameters.GetIV()));
                return new CipherBuilderImpl<ParametersWithIV>(parameters, cipher);
            }

            public IMacFactory<AuthenticationParameters> CreateMacFactory(AuthenticationParameters algorithmDetails)
            {
                IEngineProvider<IMac> macProvider = ProviderUtils.CreateMacProvider("FipsAES", algorithmDetails, aesEngineProvider);
               
                return new MacFactory<AuthenticationParameters>(algorithmDetails, macProvider, (algorithmDetails.MacSizeInBits + 7) / 8);
            }

            public IMacFactory<AuthenticationParametersWithIV> CreateMacFactory(AuthenticationParametersWithIV algorithmDetails)
            {
                IEngineProvider<IMac> macProvider = ProviderUtils.CreateMacProvider("FipsAES", algorithmDetails, aesEngineProvider);

                return new MacFactory<AuthenticationParametersWithIV>(algorithmDetails, macProvider, (algorithmDetails.MacSizeInBits + 7) / 8);
            }

            public IBlockCipherBuilder<Parameters> CreateBlockDecryptorBuilder(Parameters parameters)
            {
                return DoCreateBlockCipherBuilder(false, parameters);
            }

            public IBlockCipherBuilder<Parameters> CreateBlockEncryptorBuilder(Parameters parameters)
            {
                return DoCreateBlockCipherBuilder(true, parameters);
            }

            private IBlockCipherBuilder<Parameters> DoCreateBlockCipherBuilder(bool forEncryption, Parameters parameters)
            {
                EngineUsage engineUsage = forEncryption ? EngineUsage.ENCRYPTION : EngineUsage.DECRYPTION;
                IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher("FipsAES", parameters.Algorithm.Mode, parameters, aesEngineProvider.CreateEngine(engineUsage));
                cipher.Init(forEncryption, null);
                return new BlockCipherBuilderImpl<Parameters>(forEncryption, parameters, cipher);
            }

            public IBlockCipherBuilder<ParametersWithIV> CreateBlockDecryptorBuilder(ParametersWithIV parameters)
            {
                return DoCreateBlockCipherBuilder(false, parameters);
            }

            public IBlockCipherBuilder<ParametersWithIV> CreateBlockEncryptorBuilder(ParametersWithIV parameters)
            {
                return DoCreateBlockCipherBuilder(true, parameters);
            }

            private IBlockCipherBuilder<ParametersWithIV> DoCreateBlockCipherBuilder(bool forEncryption, ParametersWithIV parameters)
            {
                IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher("FipsAES", parameters.Algorithm.Mode, parameters, forEncryption, aesEngineProvider);
                cipher.Init(forEncryption, new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()));
                return new BlockCipherBuilderImpl<ParametersWithIV>(forEncryption, parameters, cipher);
            }

            public IAeadCipherBuilder<AuthenticationParametersWithIV> CreateAeadDecryptorBuilder(AuthenticationParametersWithIV parameters)
            {
                return DoCreateAeadCipherBuilder(false, parameters);
            }

            public IAeadCipherBuilder<AuthenticationParametersWithIV> CreateAeadEncryptorBuilder(AuthenticationParametersWithIV parameters)
            {
                return DoCreateAeadCipherBuilder(true, parameters);
            }

            private IAeadCipherBuilder<AuthenticationParametersWithIV> DoCreateAeadCipherBuilder(bool forEncryption, AuthenticationParametersWithIV parameters)
            {
                IAeadBlockCipher cipher = ProviderUtils.CreateAeadCipher("FipsAES", parameters.Algorithm.Mode, parameters, forEncryption, aesEngineProvider);
                cipher.Init(forEncryption, new AeadParameters(null, parameters.MacSizeInBits, parameters.GetIV()));
                return new AeadCipherBuilderImpl<AuthenticationParametersWithIV>(forEncryption, parameters, cipher);
            }
        }

        internal class Service
            : IAeadBlockCipherService
        {
            private readonly bool approvedOnlyMode;
            private readonly Algorithm keyAlg;
            private readonly byte[] keyBytes;
            private readonly Provider prov;
            private readonly Aes.ProviderForIV genProvForIV;

            internal Service(FipsAes.Key key)
            {
                approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                keyAlg = key.Algorithm;
                keyBytes = key.GetKeyBytes();

                IEngineProvider<Internal.IBlockCipher> engineProvider = new EngineProvider(new KeyParameter(keyBytes));

                this.prov = new Provider("AES", engineProvider);

                if (!CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    this.genProvForIV = new Aes.ProviderForIV("AES", engineProvider);
                }
            }

            public IAeadCipherBuilder<A> CreateAeadDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                return ((IAeadDecryptorBuilderProvider<A>)prov).CreateAeadDecryptorBuilder(algorithmDetails);
            }

            public IAeadCipherBuilder<A> CreateAeadEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                return ((IAeadEncryptorBuilderProvider<A>)prov).CreateAeadEncryptorBuilder(algorithmDetails);
            }

            public IBlockCipherBuilder<A> CreateBlockDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                try
                {
                    return ((IBlockDecryptorBuilderProvider<A>)prov).CreateBlockDecryptorBuilder(algorithmDetails);
                }
                catch (InvalidCastException e)
                {
                    if (!AlgorithmModeUtils.isBlockCipherMode(algorithmDetails.Algorithm))
                    {
                        throw new NotSupportedException("cannot create a block decryptor from non-block mode", e);
                    }

                    throw e;
                }
            }

            public IBlockCipherBuilder<A> CreateBlockEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                try
                {
                    return ((IBlockEncryptorBuilderProvider<A>)prov).CreateBlockEncryptorBuilder(algorithmDetails);
                }
                catch (InvalidCastException e)
                {
                    if (!AlgorithmModeUtils.isBlockCipherMode(algorithmDetails.Algorithm))
                    {
                        throw new NotSupportedException("cannot create a block encryptor from non-block mode", e);
                    }
                    throw e;
                }
            }

            public ICipherBuilder<A> CreateDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                if (algorithmDetails is Aes.ParametersWithIV)
                {
                    CryptoServicesRegistrar.GeneralModeCheck(approvedOnlyMode, algorithmDetails.Algorithm);

                    return ((IDecryptorBuilderProvider<A>)genProvForIV).CreateDecryptorBuilder(algorithmDetails);
                }
                return ((IDecryptorBuilderProvider<A>)prov).CreateDecryptorBuilder(algorithmDetails);
            }

            public ICipherBuilder<A> CreateEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                if (algorithmDetails is Aes.ParametersWithIV)
                {
                    CryptoServicesRegistrar.GeneralModeCheck(approvedOnlyMode, algorithmDetails.Algorithm);

                    return ((IEncryptorBuilderProvider<A>)genProvForIV).CreateEncryptorBuilder(algorithmDetails);
                }
                return ((IEncryptorBuilderProvider<A>)prov).CreateEncryptorBuilder(algorithmDetails);
            }

            public IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails) where A : ISymmetricWrapParameters<A, Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                return ((IKeyUnwrapperProvider<A>)prov).CreateKeyUnwrapper(algorithmDetails);
            }

            public IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails) where A : ISymmetricWrapParameters<A, Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                return ((IKeyWrapperProvider<A>)prov).CreateKeyWrapper(algorithmDetails);
            }

            public IMacFactory<A> CreateMacFactory<A>(A algorithmDetails) where A : IAuthenticationParameters<A, Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm);

                return ((IMacFactoryProvider<A>)prov).CreateMacFactory(algorithmDetails);
            }
        }

        private static void ValidateKeySize(byte[] keyBytes)
        {
            switch (keyBytes.Length)
            {
                case 16:
                case 24:
                case 32:
                    break;
                default:
                    throw new ArgumentException("unknown key size");
            }
        }

        private static void ValidateKeyUse(Algorithm keyAlg, byte[] keyBytes, Algorithm usageAlg)
        {
            // FSM_STATE:5.10,"AES KEY VALIDITY TEST", "The module is validating the size and purpose of an AES key"
            // FSM_TRANS:5.AES.0,"CONDITIONAL TEST", "AES KEY VALIDITY TEST", "Invoke Validity test on AES key"
            int keyLength = keyBytes.Length * 8;
            if (keyLength != 128 && keyLength != 192 && keyLength != 256)
            {
                // FSM_TRANS:5.AES.2,"AES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on AES key failed"
                throw new IllegalKeyException("AES key must be of length 128, 192, or 256");
            }

            if (keyAlg != Alg && keyAlg != Alg128 && keyAlg != Alg192 && keyAlg != Alg256)
            {
                if (keyAlg != usageAlg)
                {
                    // FSM_TRANS:5.AES.2,"AES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on AES key failed"
                    throw new IllegalKeyException("FIPS Key not for specified algorithm");
                }
            }

            // FSM_TRANS:5.AES.1,"AES KEY VALIDITY TEST", "CONDITIONAL TEST", "Validity test on AES key successful"
        }

        internal static readonly IEngineProvider<Internal.IBlockCipher> ENGINE_PROVIDER;

        private class EngineProvider
            : IEngineProvider<Internal.IBlockCipher>
        {
            private readonly KeyParameter keyParameter;

            internal EngineProvider(KeyParameter keyParameter)
            {
                this.keyParameter = keyParameter;
            }

            public Internal.IBlockCipher CreateEngine(EngineUsage usage)
            {
                Internal.IBlockCipher engine = SelfTestExecutor.Validate(Alg, new AesFastEngine(), new AesSelfTest());
                if (keyParameter != null)
                {
                    engine.Init(usage == EngineUsage.ENCRYPTION, keyParameter);
                }

                return engine;
            }
        }

        private class AesSelfTest
            : VariantKatTest<AesFastEngine>
        {
            internal override void Evaluate(AesFastEngine aesEngine)
            {
                byte[] input = Hex.Decode("00112233445566778899aabbccddeeff");
                byte[] tmp = new byte[input.Length];

                KeyParameter key = new KeyParameter(Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

                aesEngine.Init(true, key);

                aesEngine.ProcessBlock(input, 0, tmp, 0);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesEcbEnc], tmp))
                {
                    Fail("failed self test on encryption");
                }

                aesEngine.Init(false, key);

                aesEngine.ProcessBlock(tmp, 0, tmp, 0);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesEcbDec], tmp))
                {
                    Fail("failed self test on decryption");
                }
            }
        }

        private static void CcmStartUpTest(EngineProvider provider)
        {
            SelfTestExecutor.Validate(Ccm.Algorithm, provider, new CcmStartupTest());
        }

        private class CcmStartupTest
            : VariantKatTest<EngineProvider>
        {
            internal override void Evaluate(EngineProvider provider)
            {
                byte[] K = Hex.Decode("404142434445464748494a4b4c4d4e4f");
                byte[] N = Hex.Decode("10111213141516");
                byte[] A = Hex.Decode("0001020304050607");
                byte[] P = Hex.Decode("20212223");
                byte[] C = Hex.Decode("7162015b4dac255d");
                byte[] T = Hex.Decode("6084341b");

                CcmBlockCipher encCipher = new CcmBlockCipher(provider.CreateEngine(EngineUsage.GENERAL));
                CcmBlockCipher decCipher = new CcmBlockCipher(provider.CreateEngine(EngineUsage.GENERAL));
                int macSize = T.Length * 8;

                KeyParameter keyParam = new KeyParameter(K);

                encCipher.Init(true, new AeadParameters(keyParam, macSize, N, A));
                
                byte[] enc = new byte[C.Length];

                int len = encCipher.ProcessBytes(P, 0, P.Length, enc, 0);

                encCipher.DoFinal(enc, len);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesCcmEnc], enc))
                {
                    Fail("encrypted stream fails to match in self test");
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesCcmEncTag], encCipher.GetMac()))
                {
                    Fail("MAC fails to match in self test encrypt");
                }

                decCipher.Init(false, new AeadParameters(keyParam, macSize, N, A));

                byte[] tmp = new byte[enc.Length];

                len = decCipher.ProcessBytes(enc, 0, enc.Length, tmp, 0);

                len += decCipher.DoFinal(tmp, len);

                byte[] dec = new byte[len];

                Array.Copy(tmp, 0, dec, 0, len);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesCcmDec], dec))
                {
                    Fail("decrypted stream fails to match in self test");
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesCcmDecTag], decCipher.GetMac()))
                {
                    Fail("MAC fails to match in self test");
                }
            }
        }

        private static void CMacStartUpTest(EngineProvider provider)
        {
            SelfTestExecutor.Validate(CMac.Algorithm, provider, new CMacStartupTest());
        }

        private class CMacStartupTest
            : IBasicKatTest<EngineProvider>
        {
            public bool HasTestPassed(EngineProvider provider)
            {
                byte[] keyBytes128 = Hex.Decode("2b7e151628aed2a6abf7158809cf4f3c");
                byte[] input16 = Hex.Decode("6bc1bee22e409f96e93d7e117393172a");
                byte[] output_k128_m16 = Hex.Decode("070a16b46b4d4144f79bdd9dd04a287c");

                IMac mac = new CMac(provider.CreateEngine(EngineUsage.GENERAL), 128);

                //128 bits key
                KeyParameter key = new KeyParameter(keyBytes128);

                byte[] output = Macs.DoFinal(mac, key, input16, 0, input16.Length);

                return Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesCMacTag], output);
            }
        }

        private static void GcmStartUpTest(EngineProvider provider)
        {
            SelfTestExecutor.Validate(Gcm.Algorithm, provider, new GcmStartupTest());
        }

        private class GcmStartupTest
            : VariantKatTest<EngineProvider>
        {
            internal override void Evaluate(EngineProvider provider)
            {
                GcmBlockCipher encCipher = new GcmBlockCipher(provider.CreateEngine(EngineUsage.GENERAL));
                GcmBlockCipher decCipher = new GcmBlockCipher(provider.CreateEngine(EngineUsage.GENERAL));

                byte[] K = Hex.Decode("feffe9928665731c6d6a8f9467308308");
                byte[] P = Hex.Decode("d9313225f88406e5a55909c5aff5269a"
                    + "86a7a9531534f7da2e4c303d8a318a72"
                    + "1c3c0c95956809532fcf0e2449a6b525"
                    + "b16aedf5aa0de657ba637b39");
                byte[] A = Hex.Decode("feedfacedeadbeeffeedfacedeadbeef"
                    + "abaddad2");
                byte[] IV = Hex.Decode("cafebabefacedbaddecaf888");
                byte[] C = Hex.Decode("42831ec2217774244b7221b784d0d49c"
                    + "e3aa212f2c02a4e035c17e2329aca12e"
                    + "21d514b25466931c7d8f6a5aac84aa05"
                    + "1ba30b396a0aac973d58e091");
                byte[] T = Hex.Decode("5bc94fbc3221a5db94fae95ae7121a47");

                ICipherParameters parameters = new AeadParameters(new KeyParameter(K), T.Length * 8, IV, A);

                encCipher.Init(true, parameters);
                decCipher.Init(false, parameters);

                byte[] enc = new byte[encCipher.GetOutputSize(P.Length)];

                int len = encCipher.ProcessBytes(P, 0, P.Length, enc, 0);
                len += encCipher.DoFinal(enc, len);

                if (enc.Length != len)
                {
                    Fail("encryption reported incorrect length");
                }

                byte[] mac = encCipher.GetMac();

                byte[] data = new byte[P.Length];
                Array.Copy(enc, 0, data, 0, data.Length);
                byte[] tail = new byte[enc.Length - P.Length];
                Array.Copy(enc, P.Length, tail, 0, tail.Length);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesGcmEnc], data))
                {
                    Fail("incorrect encrypt");
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesGcmEncTag], mac))
                {
                    Fail("getMac() returned wrong MAC");
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesGcmEncTag], tail))
                {
                    Fail("stream contained wrong MAC");
                }

                byte[] dec = new byte[decCipher.GetOutputSize(enc.Length)];

                len = decCipher.ProcessBytes(enc, 0, enc.Length, dec, 0);
                decCipher.DoFinal(dec, len);
                mac = decCipher.GetMac();

                data = new byte[C.Length];
                Array.Copy(dec, 0, data, 0, data.Length);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesGcmDec], data))
                {
                    Fail("incorrect decrypt");
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.AesGcmDecTag], mac))
                {
                    Fail("incorrect MAC on decrypt");
                }
            }
        }
    }
}

