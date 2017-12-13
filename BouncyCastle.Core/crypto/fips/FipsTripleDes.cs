using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved implementations of Triple-DES based algorithms.
    /// </summary>
    public class FipsTripleDes
    {
        /// <summary>
        /// Raw Triple-DES algorithm, can be used for creating general purpose Triple-DES keys.
        /// </summary>
        public static readonly FipsAlgorithm Alg = new FipsAlgorithm("TripleDES");

        /// <summary>
        /// Algorithm tag for Triple-DES with 128 bit (112 effective bits) key.
        /// </summary>
        public static readonly FipsAlgorithm Alg112 = new FipsAlgorithm("TripleDES");

        /// <summary>
        /// Algorithm tag for Triple-DES with 192 bit (168 effective bits) key.
        /// </summary>
        public static readonly FipsAlgorithm Alg168 = new FipsAlgorithm("TripleDES");

        /// <summary>
        /// Parameters to use for creating a 112 bit Triple-DES key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen112 = new KeyGenerationParameters(128);

        /// <summary>
        /// Parameters to use for creating a 168 bit Triple-DES key generator.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen168 = new KeyGenerationParameters(192);

        /// <summary>
        /// Triple-DES in electronic code book (ECB) mode.
        /// </summary>
        public static readonly Parameters Ecb = new Parameters(new FipsAlgorithm(Alg, AlgorithmMode.ECB));

        /// <summary>
        /// Triple-DES in cipher block chaining (CBC) mode.
        /// </summary>
        public static readonly ParametersWithIV Cbc = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CBC));

        /// <summary>
        /// Triple-DES in cipher feedback (CFB) mode, 8 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Cfb8 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CFB8));

        /// <summary>
        /// Triple-DES in cipher feedback (CFB) mode, 128 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Cfb64 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CFB64));

        /// <summary>
        /// Triple-DES in output feedback (OFB) mode - 128 bit block size.
        /// </summary>
        public static readonly ParametersWithIV Ofb = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.OFB64));

        /// <summary>
        ///  Triple-DES in counter (CTR) mode.
        /// </summary>
        public static readonly ParametersWithIV Ctr = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CTR));

        /// <summary>
        ///  Triple-DES in CBC mode with cipher text stealing type CS1.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS1 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CS1));

        /// <summary>
        ///  Triple-DES in CBC mode with cipher text stealing type CS2.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS2 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CS2));

        /// <summary>
        ///  Triple-DES in CBC mode with cipher text stealing type CS3.
        /// </summary>
        public static readonly ParametersWithIV CbcWithCS3 = new ParametersWithIV(new FipsAlgorithm(Alg, AlgorithmMode.CS3));

        /// <summary>
        /// Triple-DES as a FIPS SP800-38F/RFC 3394 key wrapper.
        /// </summary>
        public static readonly WrapParameters TKW = new WrapParameters(new FipsAlgorithm(Alg, AlgorithmMode.WRAP));

        /// <summary>
        /// Triple-DES cipher-based CMAC algorithm.
        /// </summary>
        public static readonly AuthenticationParameters CMac = new AuthenticationParameters(new FipsAlgorithm(Alg, AlgorithmMode.CMAC), 64);

        static FipsTripleDes()
        {
            EngineProvider provider = new EngineProvider(null);

            // FSM_STATE:3.TDES.0,"TDES ENCRYPT DECRYPT KAT", "The module is performing TDES encrypt and decrypt KAT self-test"
            // FSM_TRANS:3.TDES.0,"POWER ON SELF-TEST","TDES ENCRYPT DECRYPT KAT", "Invoke TDES Encrypt/Decrypt KAT self-test"
            provider.CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.TDES.1,"TDES ENCRYPT DECRYPT KAT", "POWER ON SELF-TEST", "TDES Encrypt/Decrypt KAT self-test successful completion"

            // FSM_STATE:3.TDES.1,"TDES-CMAC GENERATE VERIFY KAT", "The module is performing TDES-CMAC generate and verify KAT self-test"
            // FSM_TRANS:3.TDES.2, "POWER ON SELF-TEST", "TDES-CMAC GENERATE VERIFY KAT", "Invoke TDES CMAC Generate/Verify KAT self-test"
            CMacStartUpTest(provider);
            // FSM_TRANS:3.TDES.3, "TDES-CMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST", "TDES CMAC Generate/Verify KAT self-test successful completion"

            ENGINE_PROVIDER = provider;
        }

        /// <summary>
        /// Triple-DES key class.
        /// </summary>
        public class Key
            : SymmetricSecretKey, ISymmetricKey, ICryptoServiceType<IBlockCipherService>, IServiceProvider<IBlockCipherService>
        {
            public Key(byte[] keyBytes)
                : base(FipsTripleDes.Alg, keyBytes)
            {
                ValidateKeySize(keyBytes);
            }

            public Key(IParameters<Algorithm> parameterSet, byte[] bytes)
                : base(parameterSet, bytes)
            {
                ValidateKeySize(bytes);
            }

            public Key(FipsAlgorithm algorithm, byte[] bytes)
                : base(algorithm, bytes)
            {
                if (algorithm == Alg112 && bytes.Length != 16)
                {
                    throw new ArgumentException("Key must be 128 bits long");
                }
                else if (algorithm == Alg168 && bytes.Length != 24)
                {
                    throw new ArgumentException("Key must be 192 bits long");
                }
                else
                {
                    ValidateKeySize(bytes);
                }
            }

            Func<IKey, IBlockCipherService> IServiceProvider<IBlockCipherService>.GetFunc(SecurityContext context)
            {
                return (key) => new Service(this);
            }
        }

        /// <summary>
        /// Triple-DES key generation parameters base class.
        /// </summary>
        public class KeyGenerationParameters
            : IParameters<Algorithm>, IGenerationServiceType<KeyGenerator>, IGenerationService<KeyGenerator>
        {
            private readonly int sizeInBits;

            internal KeyGenerationParameters(int sizeInBits)
            {
                this.sizeInBits = sizeInBits;
            }

            public int KeySize
            {
                get { return sizeInBits; }
            }

            public Algorithm Algorithm
            {
                get { return Alg; }
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyGenerator> IGenerationService<KeyGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Triple-DES key generator.
        /// </summary>
        public class KeyGenerator
            : ISymmetricKeyGenerator<Key>
        {
            private readonly FipsAlgorithm algorithm;
            private readonly int keySizeInBits;
            private readonly SecureRandom random;

            public KeyGenerator(KeyGenerationParameters keyGenParams, SecureRandom random)
                : this(Alg, keyGenParams, random)
            {

            }

            public KeyGenerator(FipsParameters parameterSet, KeyGenerationParameters keyGenParams, SecureRandom random)
                : this(parameterSet.Algorithm, keyGenParams, random)
            {

            }

            private KeyGenerator(FipsAlgorithm algorithm, KeyGenerationParameters keyGenParams, SecureRandom random)
            {
                int keySizeInBits = keyGenParams.KeySize;

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    Utils.ValidateKeyGenRandom(random, 112, algorithm);

                    if (keySizeInBits != 168 && keySizeInBits != 192)
                    {
                        throw new ArgumentException("Attempt to create key with unapproved key size [" + keySizeInBits + "]: " + algorithm.Name);
                    }
                }
                else
                {
                    if (keySizeInBits != 112 && keySizeInBits != 168 && keySizeInBits != 128 && keySizeInBits != 192)
                    {
                        throw new ArgumentException("Attempt to create key with invalid key size [" + keySizeInBits + "]: " + algorithm.Name);
                    }
                }

                this.algorithm = algorithm;
                this.keySizeInBits = keySizeInBits;
                this.random = random;
            }

            public Key GenerateKey()
            {
                CipherKeyGenerator cipherKeyGenerator = new DesEdeKeyGenerator(algorithm);
                cipherKeyGenerator.Init(new Internal.KeyGenerationParameters(random, keySizeInBits));
                return new Key(algorithm, cipherKeyGenerator.GenerateKey());
            }
        }

        /// <summary>
        /// Base class for simple Triple-DES parameters.
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
        /// Base class for Triple-DES parameters requiring an initialization vector.
        /// </summary>
        public class ParametersWithIV
            : ParametersWithIV<ParametersWithIV, FipsAlgorithm>
        {
            internal ParametersWithIV(FipsAlgorithm algorithm)
                : this(algorithm, null)
            {
            }

            private ParametersWithIV(FipsAlgorithm algorithm, byte[] iv)
                : base(algorithm, 8, iv)
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
        /// Base class for Triple-DES key wrap parameters.
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

        internal class Provider
            :   IBlockEncryptorBuilderProvider<Parameters>, IBlockEncryptorBuilderProvider<ParametersWithIV>, IEncryptorBuilderProvider<ParametersWithIV>,
                IBlockDecryptorBuilderProvider<Parameters>, IBlockDecryptorBuilderProvider<ParametersWithIV>, IDecryptorBuilderProvider<ParametersWithIV>,
                IKeyWrapperProvider<WrapParameters>, IKeyUnwrapperProvider<WrapParameters>,
                IMacFactoryProvider<AuthenticationParameters>
        {
            private readonly IEngineProvider<Internal.IBlockCipher> desEdeEngineProvider;

            public Provider(String name, IEngineProvider<Internal.IBlockCipher> engine)
            {
                this.desEdeEngineProvider = engine;
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
                return ProviderUtils.CreateWrapper("FipsTripleDes", parameters.Algorithm.Mode, parameters.IsUsingInverseFunction, forWrapping, desEdeEngineProvider);
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
                IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher("FipsTripleDes", parameters.Algorithm.Mode, parameters, forEncryption, desEdeEngineProvider);
                cipher.Init(forEncryption, Internal.Parameters.ParametersWithIV.ApplyOptionalIV(null, parameters.GetIV()));
                return new CipherBuilderImpl<ParametersWithIV>(parameters, cipher);
            }

            public IMacFactory<AuthenticationParameters> CreateMacFactory(AuthenticationParameters algorithmDetails)
            {
                IEngineProvider<IMac> macProvider = ProviderUtils.CreateMacProvider("FipsTripleDes", algorithmDetails, desEdeEngineProvider);

                return new MacFactory<AuthenticationParameters>(algorithmDetails, macProvider, (algorithmDetails.MacSizeInBits + 7) / 8);
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
                IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher("FipsTripleDES", parameters.Algorithm.Mode, parameters, desEdeEngineProvider.CreateEngine(engineUsage));
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
                IBufferedCipher cipher = ProviderUtils.CreateBufferedCipher("FipsTripleDes", parameters.Algorithm.Mode, parameters, forEncryption, desEdeEngineProvider);
                cipher.Init(forEncryption, new Internal.Parameters.ParametersWithIV(null, parameters.GetIV()));
                return new BlockCipherBuilderImpl<ParametersWithIV>(forEncryption, parameters, cipher);
            }
        }

        internal class Service
            : IBlockCipherService
        {
            private readonly bool approvedOnlyMode;
            private readonly Algorithm keyAlg;
            private readonly byte[] keyBytes;
            private readonly Provider prov;
            private readonly TripleDes.ProviderForIV genProvForIV;

            internal Service(Key key)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.keyAlg = key.Algorithm;
                this.keyBytes = key.GetKeyBytes();

                IEngineProvider<Internal.IBlockCipher> engineProvider = new EngineProvider(new KeyParameter(keyBytes));
                this.prov = new Provider("FipsTripleDes", engineProvider);

                if (!CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    this.genProvForIV = new TripleDes.ProviderForIV("FipsTripleDes", engineProvider);
                }
            }

            public IBlockCipherBuilder<A> CreateBlockDecryptorBuilder<A>(A algorithmDetails)
                where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, true);

                return ((IBlockDecryptorBuilderProvider<A>)prov).CreateBlockDecryptorBuilder(algorithmDetails);
            }

            public IBlockCipherBuilder<A> CreateBlockEncryptorBuilder<A>(A algorithmDetails)
                where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, false);

                return ((IBlockEncryptorBuilderProvider<A>)prov).CreateBlockEncryptorBuilder(algorithmDetails);
            }

            public ICipherBuilder<A> CreateDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, true);

                if (algorithmDetails is TripleDes.ParametersWithIV)
                {
                    CryptoServicesRegistrar.GeneralModeCheck(approvedOnlyMode, algorithmDetails.Algorithm);

                    return ((IDecryptorBuilderProvider<A>)genProvForIV).CreateDecryptorBuilder(algorithmDetails);
                }
                return ((IDecryptorBuilderProvider<A>)prov).CreateDecryptorBuilder(algorithmDetails);
            }

            public ICipherBuilder<A> CreateEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, false);

                if (algorithmDetails is TripleDes.ParametersWithIV)
                {
                    CryptoServicesRegistrar.GeneralModeCheck(approvedOnlyMode, algorithmDetails.Algorithm);

                    return ((IEncryptorBuilderProvider<A>)genProvForIV).CreateEncryptorBuilder(algorithmDetails);
                }

                return ((IEncryptorBuilderProvider<A>)prov).CreateEncryptorBuilder(algorithmDetails);
            }

            public IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails)
                where A : ISymmetricWrapParameters<A, Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, true);

                return ((IKeyUnwrapperProvider<A>)prov).CreateKeyUnwrapper(algorithmDetails);
            }

            public IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails)
                where A : ISymmetricWrapParameters<A, Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, false);

                return ((IKeyWrapperProvider<A>)prov).CreateKeyWrapper(algorithmDetails);
            }

            public IMacFactory<A> CreateMacFactory<A>(A algorithmDetails)
                where A : IAuthenticationParameters<A, Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "Service");

                ValidateKeyUse(keyAlg, keyBytes, algorithmDetails.Algorithm, true);

                return ((IMacFactoryProvider<A>)prov).CreateMacFactory(algorithmDetails);
            }
        }

        private static void ValidateKeySize(byte[] keyBytes)
        {
            switch (keyBytes.Length)
            {
                case 16:
                case 24:
                    break;
                default:
                    throw new ArgumentException("unknown key size");
            }
        }

        private static void ValidateKeyUse(Algorithm keyAlg, byte[] keyBytes, Algorithm usageAlg, bool forReading)
        {
            // FSM_STATE:5.11,"TDES KEY VALIDITY TEST", "The module is validating the size and purpose of an TDES key"
            // FSM_TRANS:5.TDES.0,"CONDITIONAL TEST", "TDES KEY VALIDITY TEST", "Invoke Validity test on TDES key"
            int keyLength = keyBytes.Length * 8;
            if (!forReading)      // decryption using 2 key TDES okay,
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    if (keyLength == 128)
                    {
                        // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                        throw new IllegalKeyException("key must be of length 192 bits: " + usageAlg.Name);
                    }

                    if (!DesEdeParameters.IsReal3Key(keyBytes))
                    {
                        // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                        throw new IllegalKeyException("key not real 3-Key TripleDES key");
                    }
                }
            }

            if (!Properties.IsOverrideSet("Org.BouncyCastle.TripleDes.AllowWeak"))
            {
                if (!forReading)
                {
                    if (!DesEdeParameters.IsRealEdeKey(keyBytes))
                    {
                        // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                        throw new IllegalKeyException("attempt to use repeated DES key: " + usageAlg.Name);
                    }
                    if (DesEdeParameters.IsWeakKey(keyBytes, 0, keyBytes.Length))
                    {
                        // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                        throw new IllegalKeyException("attempt to use weak key: " + usageAlg.Name);
                    }
                }
            }

            if (keyAlg != Alg && keyAlg != Alg112 && keyAlg != Alg168)
            {
                if (keyAlg != usageAlg)
                {
                    // FSM_TRANS:5.TDES.2,"TDES KEY VALIDITY TEST", "USER COMMAND REJECTED", "Validity test on TDES key failed"
                    throw new IllegalKeyException("FIPS key not for specified algorithm");
                }
            }

            // FSM_TRANS:5.TDES.0,"TDES KEY VALIDITY TEST", "CONDITIONAL TEST", "Validity test on TDES key successful"
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
                Internal.IBlockCipher engine = SelfTestExecutor.Validate(Alg, new DesEdeEngine(), new TripleDesSelfTest());
                if (keyParameter != null)
                {
                    engine.Init(usage == EngineUsage.ENCRYPTION, keyParameter);
                }

                return engine;
            }
        }

        private class TripleDesSelfTest
            : VariantKatTest<DesEdeEngine>
        {
            internal override void Evaluate(DesEdeEngine tripleDesEngine)
            {
                byte[] input = Hex.Decode("4e6f77206973207468652074696d6520666f7220616c6c20");
                byte[] output = Hex.Decode("f7cfbe5e6c38b35a62815c962fcaf7a863af5450ec85fdab");
                byte[] tmp = new byte[input.Length];

                KeyParameter key = new KeyParameter(Hex.Decode("0102020404070708080b0b0d0d0e0e101013131515161619"));

                tripleDesEngine.Init(true, key);

                tripleDesEngine.ProcessBlock(input, 0, tmp, 0);
                tripleDesEngine.ProcessBlock(input, 8, tmp, 8);
                tripleDesEngine.ProcessBlock(input, 16, tmp, 16);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.TripleDesEcbEnc], tmp))
                {
                    Fail("failed self test on encryption");
                }

                tripleDesEngine.Init(false, key);

                tripleDesEngine.ProcessBlock(tmp, 0, tmp, 0);
                tripleDesEngine.ProcessBlock(tmp, 8, tmp, 8);
                tripleDesEngine.ProcessBlock(tmp, 16, tmp, 16);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.TripleDesEcbDec], tmp))
                {
                    Fail("failed self test on decryption");
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
                byte[] input16 = Hex.Decode("6bc1bee22e409f96e93d7e117393172a");
                byte[] output_k128_m16 = Hex.Decode("c0b9bbee139722ab");

                IMac mac = new CMac(provider.CreateEngine(EngineUsage.GENERAL), 64);

                //128 bytes key

                KeyParameter key = new KeyParameter(Hex.Decode("0102020404070708080b0b0d0d0e0e101013131515161619"));

                byte[] output = Macs.DoFinal(mac, key, input16, 0, input16.Length);

                return Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.TripleDesCMacTag], output);
            }
        }
    }
}
