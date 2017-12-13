using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Signers;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Internal.Encodings;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Crypto.Internal.Digests;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved implementations of RSA algorithms.
    /// </summary>
    public class FipsRsa
    {
        public static readonly FipsAlgorithm Alg = new FipsAlgorithm("RSA");

        /// <summary>
        ///  RSA OAEP key wrap algorithm parameter source - default is SHA-384
        /// </summary>
        public static readonly OaepWrapParameters WrapOaep = new OaepWrapParameters(new FipsAlgorithm(Alg, AlgorithmMode.OAEP), FipsShs.Sha384);

        /// <summary>
        /// RSA PKCS#1 v1.5 signature  algorithm parameter source - default is SHA-384
        /// </summary>
        public static readonly SignatureParameters Pkcs1v15 = new SignatureParameters(new FipsAlgorithm(Alg, AlgorithmMode.PKCSv1_5), FipsShs.Sha384);

        /// <summary>
        /// RSA X9.31 signature algorithm parameter source - default is SHA-384
        /// </summary>
        public static readonly SignatureParameters X931 = new SignatureParameters(new FipsAlgorithm(Alg, AlgorithmMode.X931), FipsShs.Sha384);

        /// <summary>
        /// RSA PSS signature  algorithm parameter source - default is SHA-384
        /// </summary>
        public static readonly PssSignatureParameters Pss = new PssSignatureParameters(new FipsAlgorithm(Alg, AlgorithmMode.PSS), FipsShs.Sha384, FipsShs.Sha384, 0, null);

        // Public exponent bounds
        private static readonly BigInteger MIN_PUB_EXP = BigInteger.ValueOf(0x10001);
        private static readonly BigInteger MAX_PUB_EXP = BigInteger.One.ShiftLeft(256).Subtract(BigInteger.One);

        // KAT parameters
        private static readonly BigInteger katE = new BigInteger("10001", 16);
        private static readonly BigInteger katM = new BigInteger("83ca29fa6f3da1a20a7d64c741c502def9dff5630c94ca0c674a7602aea3436d432c94e3fe9f8cea4a7975ffa5228cba39acb6d1262c3453280bd8352b0dc7fb0a343f62b2c1405baf44c0f6b37edc94f63de8f772dc30e3b5003ff9a35befa02540e08b128718870fab40dcd91575b6592bb143cc3f29aa82fce7ee72952601c0c815396a9ad382c0a79e494727478606bf92d7b1c445b73368b4d7480500091de498b365719ec9c9b76f37cc97d13d7ce830248f4df2cdc73433a9b5d3fe29122bfdb113be45444b15652059eb51085dfe354d0c87256e6a51c6902ce56d3967dcf32f3bc9464ab437ac4030d00c1e53b4da74b9e70c47a5842f3b4d4dd6c7", 16);
        private static readonly BigInteger katD = new BigInteger("22b248d6fc0e77cd5781a7d4a5c61e7961c3cab0e7110d18b2e0f1acc7198898ed8481367d44b82ebea8b79e3475a2232d28018192d1347d681fa62e6945598f0822b54560d66c0137659c7fd6c5e180fe4b5258434f2137f1e13cf696419016d377ff25de1cdf223fc7d06dd46147fa58039ec9c0ae286411d44fa3815b2f040895344a413ba141b4228a704a75883caaa3e9d2ace0d28c179acb571ca8ce0d1c3a0cf9cda8b0088b919a4833f5b46ce556faa923ea5b852a48f153ca6fc26730496d7f06691e08edac984870517d2ef689a94ad23c16d471c9a477d82fd225382a4d1ae1b934bf79f2adf3353c557888e056822809dfb561bbef946c1404d1", 16);
        private static readonly BigInteger katP = new BigInteger("df26154977b823cbee3e1861b239197310bc3115ee46e7e70bf6dd826aa834fcdafb8d940b77e43e63c073b2efceaa24805c232a3011fd8b2ac323442d89f246a024c843586174d28475fbf7eca079fae8bbe5263cdef074be0a9a07a37bdad3e72b4b44a39a70415db4b0f7f65515f6806ef88b97f935b8d6d5918feff69edd", 16);
        private static readonly BigInteger katQ = new BigInteger("9730fcb5f8e93cb4df58b80ab3e9b7f014a87b90953c26a29277771965bf2720e1808adf55aa5ac4702ba813eb2643d03a89dad3a3767beddd3fa98148057c8398a0106b086caef10603977e69ffe3e513531c7b456bb7079c57761a7eacde4218c08897ac17d4de7a5b19d192b5706694cbb162c9f95b0154232fc7bd0107f3", 16);
        private static readonly BigInteger katDP = new BigInteger("dba3666c6bb40937de85ac05ed201a9691304ab82552114bef10cb3264bcaf7afa278350e680d95d375de40389da46c9aab605beae95e6932641efe259585fe97812fc329d393f7d3df7cb4c59d2127e0eb97270d29534e41371e7ee00d215af60e7d22bfb44359d81182adfc5cc35d3ecd24d3d491677f43930f9174dbfd6d9", 16);
        private static readonly BigInteger katDQ = new BigInteger("82d8a47ca054ca7306b07366dfd9af94996c4eb40c53a8641e3a41dabb11b9bd5d2bb00424d170087dc36a8d027f7544eac48f9b85e66ecea7220782996016289598415d40473f07dcda92eb96b51cf80dc769e8cd65b15b66d4d2a38f69f05867af89072aaadd5145b73e1affcb02e1e4787ca630821b5e850086c36831523d", 16);
        private static readonly BigInteger katQInv = new BigInteger("c6ae6a9ff4614a08e1e501e3dd7586c7cd2e70b9e2581185194b7984452325558f576b54b177df38f6d98e2ffce835608d1d3c81fab9f3696796bd5faacf9870b5ad12868eebccb2f55cc398d70ad6197eaeb4ead5cb0415913f18306bc0327f31db0f04910aea237a657634f1ac82b03bd5b2bc30b5f89077677bd3cab0d255", 16);

        private static byte[] msg = Hex.Decode("48656c6c6f20776f726c6421");
        private static byte[] pkcs15Sig = Hex.Decode("1669b752b409a66ca38ba7e34ae2d5da4303c091255989a4369885ecbb25db3ec05b06fdb4b1be46f6ab347bad9dbbbc9facf0beb4be70bd5f2ee2760c76f0a55932dd7fb4fe5c7b18226796f955215ec6354da9b3808a0df8c2a328abdd67d537f967ea5147bb85dcd80fdcee250b9bc7cec84a08afcde82afa4e62d80bbaf00bcdaf6bbac2b4a4bd394ee223ea3ee100fd233dd40514ea7a9717bfb52370eb4157e7bd25396e9dd3e3782ec2c64db71cf8380c05d3941481af3a08003737456a00cb265efc1d0987acae40776fa497681cb987a508419cbe1e4601a5e5aef66329288453003101a375ad3ec6e4b9a82f49a0748eb024fe1ce2de910d823938");

        private static readonly RsaKeyParameters testPubKey = new RsaKeyParameters(false, katM, katE);
        private static readonly RsaPrivateCrtKeyParameters testPrivKey = new RsaPrivateCrtKeyParameters(katM, katE, katD, katP, katQ, katDP, katDQ, katQInv);

        internal static readonly EngineProvider ENGINE_PROVIDER;

        static FipsRsa()
        {
            EngineProvider provider = new EngineProvider();

            // FSM_STATE:3.RSA.0,"RSA SIGN VERIFY KAT", "The module is performing RSA sign and verify KAT self-test"
            // FSM_TRANS:3.RSA.0,"POWER ON SELF-TEST","RSA SIGN VERIFY KAT", "Invoke RSA Sign/Verify KAT self-test"
            rsaSignTest(provider);
            // FSM_TRANS:3.RSA.1,"RSA SIGN VERIFY KAT","POWER ON SELF-TEST", "RSA Sign/Verify KAT self-test successful completion"

            // FSM_STATE:3.RSA.1, "KEY TRANSPORT USING RSA VERIFY KAT", "The module is performing RSA Key Transport verify KAT self-test"
            // FSM_TRANS:3.RSA.2,"POWER ON SELF-TEST","KEY TRANSPORT USING RSA VERIFY KAT", "Invoke Key Transport Using RSA, Specific SP 800-56B KAT self-test"
            rsaKeyTransportTest(provider);
            // FSM_TRANS:3.RSA.3,"KEY TRANSPORT USING RSA VERIFY KAT", "POWER ON SELF-TEST", "Key Transport Using RSA, Specific SP 800-56B KAT self-test successful completion"

            ENGINE_PROVIDER = provider;
        }

        /// <summary>
        /// OAEP key wrap parameters base class.
        /// </summary>
        public class OaepWrapParameters : OaepParameters<OaepWrapParameters, FipsAlgorithm, FipsDigestAlgorithm>
        {
            internal OaepWrapParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm) : base(algorithm, digestAlgorithm, digestAlgorithm, null)
            {
            }

            internal OaepWrapParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm, FipsDigestAlgorithm mgfAlgorithm, byte[] encodedParams) : base(algorithm, digestAlgorithm, mgfAlgorithm, encodedParams)
            {
            }

            internal override OaepWrapParameters CreateParameter(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm, FipsDigestAlgorithm mgfAlgorithm, byte[] encodedParams)
            {
                return new OaepWrapParameters(algorithm, digestAlgorithm, mgfAlgorithm, encodedParams);
            }
        }

        /// <summary>
        /// PKCS#1.5/X9.31 signature parameters base class.
        /// </summary>
        public class SignatureParameters : SignatureParameters<SignatureParameters, FipsAlgorithm, FipsDigestAlgorithm>
        {
            internal SignatureParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm) : base(algorithm, digestAlgorithm)
            {
            }

            internal override SignatureParameters CreateParameter(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm)
            {
                return new SignatureParameters(algorithm, digestAlgorithm);
            }
        }

        /// <summary>
        /// PSS signature parameters base class.
        /// </summary>
        public class PssSignatureParameters : PssSignatureParameters<PssSignatureParameters, FipsAlgorithm, FipsDigestAlgorithm>
        {
            internal PssSignatureParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm, FipsDigestAlgorithm mgfAlgorithm, int saltLength, byte[] salt) : base(algorithm, digestAlgorithm, digestAlgorithm, saltLength, salt)
            {
            }

            internal override PssSignatureParameters CreateParameter(FipsAlgorithm algorithm, FipsDigestAlgorithm digestAlgorithm, FipsDigestAlgorithm mgfAlgorithm, int saltLength, byte[] salt)
            {
                return new PssSignatureParameters(algorithm, digestAlgorithm, mgfAlgorithm, saltLength, salt);
            }
        }

        /// <summary>
        /// Parameters for RSA key pair generation.
        /// </summary>
        public class KeyGenerationParameters : FipsParameters, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
        {
            private BigInteger publicExponent;
            private int keySize;
            private int certainty;

            /// <summary>
            /// Base constructor - a default certainty will be calculated.
            /// </summary>
            /// <param name="publicExponent">The public exponent to use.</param>
            /// <param name="keySize">The key size (in bits)</param>
            public KeyGenerationParameters(BigInteger publicExponent, int keySize) : this(Alg, publicExponent, keySize, PrimeCertaintyCalculator.GetDefaultCertainty(keySize))
            {
            }

            /// <summary>
            /// Base constructor with certainty.
            /// </summary>
            /// <param name="publicExponent">The public exponent to use.</param>
            /// <param name="keySize">The key size (in bits)</param>
            /// <param name="certainty">Certainty to use for prime number calculation.</param>
            public KeyGenerationParameters(BigInteger publicExponent, int keySize, int certainty) : this(Alg, publicExponent, keySize, certainty)
            {
            }

            internal KeyGenerationParameters(IParameters<FipsAlgorithm> parameters, KeyGenerationParameters keyGenParameters) : this(parameters.Algorithm, keyGenParameters.publicExponent, keyGenParameters.keySize, keyGenParameters.certainty)
            {
            }

            public KeyGenerationParameters For(OaepWrapParameters oaepUsage)
            {
                return new KeyGenerationParameters(oaepUsage, this);
            }

            public KeyGenerationParameters For(SignatureParameters sigUsage)
            {
                return new KeyGenerationParameters(sigUsage, this);
            }

            public KeyGenerationParameters For(PssSignatureParameters pssUsage)
            {
                return new KeyGenerationParameters(pssUsage, this);
            }

            private KeyGenerationParameters(FipsAlgorithm algorithm, BigInteger publicExponent, int keySize, int certainty) : base(algorithm)
            {
                this.publicExponent = publicExponent;
                this.keySize = keySize;
                this.certainty = certainty;

                Validate();
            }

            internal void Validate()
            {
                if (!this.publicExponent.TestBit(0))
                {
                    throw new ArgumentException("Public exponent must be an odd number: " + Algorithm.Name);
                }

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    if (this.keySize != 2048 && this.keySize != 3072)
                    {
                        throw new CryptoUnapprovedOperationError("Attempt to use RSA key size outside of accepted range - requested keySize " + keySize + " bits", Algorithm);
                    }

                    if (this.publicExponent.CompareTo(MIN_PUB_EXP) < 0)
                    {
                        throw new CryptoUnapprovedOperationError("Public exponent too small", Algorithm);
                    }

                    if (this.publicExponent.CompareTo(MAX_PUB_EXP) > 0)
                    {
                        throw new CryptoUnapprovedOperationError("Public exponent too large", Algorithm);
                    }

                    if (!this.publicExponent.TestBit(0))
                    {
                        throw new CryptoUnapprovedOperationError("Public exponent must be an odd number", Algorithm);
                    }

                    if (this.certainty < PrimeCertaintyCalculator.GetDefaultCertainty(keySize))
                    {
                        throw new CryptoUnapprovedOperationError("Prime generation certainty " + certainty + " inadequate for key of  " + keySize + " bits", Algorithm);
                    }
                }
            }

            public BigInteger PublicExponent
            {
                get
                {
                    return publicExponent;
                }
            }

            public int KeySize
            {
                get
                {
                    return keySize;
                }
            }

            public int Certainty
            {
                get
                {
                    return certainty;
                }
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyPairGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Key pair generator for RSA. Create one these via CryptoServicesRegistrar.CreateGenerator() using the KeyGenerationParameters
        /// object as the key.
        /// </summary>
        public class KeyPairGenerator : AsymmetricKeyPairGenerator<KeyGenerationParameters, AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey>
        {
            private RsaKeyPairGenerator engine = new RsaKeyPairGenerator();
            private RsaKeyGenerationParameters param;

            internal KeyPairGenerator(KeyGenerationParameters keyGenParameters, SecureRandom random) : base(keyGenParameters)
            {
                int keySize = keyGenParameters.KeySize;

                keyGenParameters.Validate();

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    Utils.ValidateKeyPairGenRandom(random, Utils.GetAsymmetricSecurityStrength(keySize), Alg);
                }

                this.param = new RsaKeyGenerationParameters(keyGenParameters.PublicExponent, random, keySize, keyGenParameters.Certainty);
                this.engine.Init(param);
            }

            public override AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> GenerateKeyPair()
            {
                AsymmetricCipherKeyPair kp = engine.GenerateKeyPair();

                RsaKeyParameters pubKey = (RsaKeyParameters)kp.Public;
                RsaPrivateCrtKeyParameters prvKey = (RsaPrivateCrtKeyParameters)kp.Private;

                FipsAlgorithm algorithm = this.Parameters.Algorithm;

                // FSM_STATE:5.5, "RSA PAIRWISE CONSISTENCY TEST", "The module is performing RSA Pairwise Consistency self-test"
                // FSM_TRANS:5.RSA.0,"CONDITIONAL TEST", "RSA PAIRWISE CONSISTENCY TEST", "Invoke RSA Pairwise Consistency test"
                ValidateKeyPair(kp);
                // FSM_TRANS:5.RSA.1,"RSA PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "RSA Pairwise Consistency test successful"

                // we register the modulus value so that is in validated modulus cache
                // otherwise the modulus will be revalidated on key construction.
                AsymmetricRsaKey.RegisterModulus(prvKey.Modulus);

                AsymmetricRsaPrivateKey privateKey = new AsymmetricRsaPrivateKey(algorithm, prvKey.Modulus, prvKey.PublicExponent, prvKey.Exponent,
                    prvKey.P, prvKey.Q, prvKey.DP, prvKey.DQ, prvKey.QInv);

                return new AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey>(new AsymmetricRsaPublicKey(algorithm, pubKey.Modulus, pubKey.Exponent),
                    privateKey);
            }
        }

        private static ICipherParameters GetPublicParameters(IKey publicKey, AsymmetricRsaKey.Usage rsaUsage)
        {
            if (publicKey is KeyWithRandom)
            {
                KeyWithRandom k = (KeyWithRandom)publicKey;

                return new ParametersWithRandom(GetPublicKeyParameters((AsymmetricRsaPublicKey)k.Key, rsaUsage), k.Random);
            }
            else
            {
                return new ParametersWithRandom(GetPublicKeyParameters((AsymmetricRsaPublicKey)publicKey, rsaUsage), CryptoServicesRegistrar.GetSecureRandom());
            }
        }

        private static ICipherParameters GetPrivateParameters(IKey privateKey, AsymmetricRsaKey.Usage rsaUsage)
        {
            if (privateKey is KeyWithRandom)
            {
                KeyWithRandom k = (KeyWithRandom)privateKey;

                return new ParametersWithRandom(GetPrivateKeyParameters((AsymmetricRsaPrivateKey)k.Key, rsaUsage), k.Random);
            }
            else
            {
                return new ParametersWithRandom(GetPrivateKeyParameters((AsymmetricRsaPrivateKey)privateKey, rsaUsage), CryptoServicesRegistrar.GetSecureRandom());
            }
        }

        internal class RsaKeyWrapper : IKeyWrapper<OaepWrapParameters>
        {
            private readonly OaepWrapParameters algorithmDetails;
            private readonly OaepEncoding wrapper;

            internal RsaKeyWrapper(OaepWrapParameters algorithmDetails, IKey rsaPublicKey)
            {
                this.algorithmDetails = algorithmDetails;
                this.wrapper = new OaepEncoding(ENGINE_PROVIDER.CreateEngine(EngineUsage.ENCRYPTION), FipsShs.CreateDigest(algorithmDetails.DigestAlgorithm), FipsShs.CreateDigest(algorithmDetails.MgfDigestAlgorithm), algorithmDetails.GetEncodingParams());

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    AsymmetricRsaPublicKey rsaKey = GetPublicKey(rsaPublicKey);
                    int bitLength = rsaKey.Modulus.BitLength;                    
                    if (bitLength != 2048 && bitLength != 3072)
                    {
                        throw new CryptoUnapprovedOperationError("Attempt to use RSA key with non-approved size: " + bitLength, rsaKey.Algorithm);
                    }
                }
                wrapper.Init(true, GetPublicParameters(rsaPublicKey, AsymmetricRsaKey.Usage.EncryptOrDecrypt));
            }

            public OaepWrapParameters AlgorithmDetails
            {
                get
                {
                    return algorithmDetails;
                }
            }

            public IBlockResult Wrap(byte[] keyData)
            {
                return new SimpleBlockResult(wrapper.ProcessBlock(keyData, 0, keyData.Length));
            }
        }

        internal class RsaKeyUnwrapper : IKeyUnwrapper<OaepWrapParameters>
        {
            private readonly OaepWrapParameters algorithmDetails;
            private readonly OaepEncoding unwrapper;

            internal RsaKeyUnwrapper(OaepWrapParameters algorithmDetails, IKey key)
            {
                this.algorithmDetails = algorithmDetails;
                this.unwrapper = new OaepEncoding(ENGINE_PROVIDER.CreateEngine(EngineUsage.DECRYPTION), FipsShs.CreateDigest(algorithmDetails.DigestAlgorithm), FipsShs.CreateDigest(algorithmDetails.MgfDigestAlgorithm), algorithmDetails.GetEncodingParams());

                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    AsymmetricRsaPrivateKey rsaKey = GetPrivateKey(key);
                    int bitLength = rsaKey.Modulus.BitLength;
                    if (bitLength != 2048 && bitLength != 3072 && bitLength != 4096)
                    {
                        throw new CryptoUnapprovedOperationError("Attempt to use RSA key with non-approved size: " + bitLength, key.Algorithm);
                    }
                }

                unwrapper.Init(false, GetPrivateParameters(key, AsymmetricRsaKey.Usage.EncryptOrDecrypt));
            }

            public OaepWrapParameters AlgorithmDetails
            {
                get
                {
                    return algorithmDetails;
                }
            }

            public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
            {
                return new SimpleBlockResult(unwrapper.ProcessBlock(cipherText, offset, length));
            }
        }

        private static void ValidateKeyPair(AsymmetricCipherKeyPair kp)
        {
            SelfTestExecutor.Validate(Alg, kp, new RsaKeyPairConsistencyTest());
        }

        private class RsaKeyPairConsistencyTest : IConsistencyTest<AsymmetricCipherKeyPair>
        {
            public bool HasTestPassed(AsymmetricCipherKeyPair kp)
            {
                byte[] data = Hex.Decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc");

                RsaBlindedEngine rsaEngine = new RsaBlindedEngine();

                rsaEngine.Init(true, kp.Public);

                byte[] encrypted = rsaEngine.ProcessBlock(data, 0, data.Length);

                if (Arrays.AreEqual(data, encrypted))
                {
                    return false;
                }

                rsaEngine.Init(false, new ParametersWithRandom(kp.Private, Utils.testRandom));

                byte[] decrypted = rsaEngine.ProcessBlock(encrypted, 0, encrypted.Length);

                return Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.RsaKeyPairConsistencyCheck], data);
            }
        }

        internal static ICipherParameters GetSigKeyParams(IKey key)
        {
            if (key is AsymmetricRsaPublicKey)
            {
                AsymmetricRsaPublicKey rsaPubKey = (AsymmetricRsaPublicKey)key;
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    int bitLength = rsaPubKey.Modulus.BitLength;

                    if (bitLength != 2048 && bitLength != 3072 && bitLength != 1024 && bitLength != 4096 && bitLength != 1536) // includes 186-2 legacy sizes
                    {
                        throw new CryptoUnapprovedOperationError("Attempt to use RSA key with non-approved size: " + bitLength, key.Algorithm);
                    }
                }

                return GetPublicKeyParameters(rsaPubKey, AsymmetricRsaKey.Usage.SignOrVerify);
            }
            else
            {
                AsymmetricRsaPrivateKey rsaPrivKey = GetPrivateKey(key);
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    int bitLength = rsaPrivKey.Modulus.BitLength;
                    if (bitLength != 2048 && bitLength != 3072)
                    {
                        throw new CryptoUnapprovedOperationError("Attempt to use RSA key with non-approved size: " + bitLength, key.Algorithm);
                    }
                }

                return GetPrivateParameters(key, AsymmetricRsaKey.Usage.SignOrVerify);
            }
        }

        private static AsymmetricRsaPrivateKey GetPrivateKey(IKey key)
        {
            if (key is KeyWithRandom)
            {
                return (AsymmetricRsaPrivateKey)((KeyWithRandom)key).Key;
            }
            else
            {
                return (AsymmetricRsaPrivateKey)key;
            }
        }

        private static AsymmetricRsaPublicKey GetPublicKey(IKey key)
        {
            if (key is KeyWithRandom)
            {
                return (AsymmetricRsaPublicKey)((KeyWithRandom)key).Key;
            }
            else
            {
                return (AsymmetricRsaPublicKey)key;
            }
        }

        internal class SignerProvider : IEngineProvider<ISigner>
        {
            private readonly SignatureParameters parameters;
            private readonly ICipherParameters sigParams;

            internal SignerProvider(SignatureParameters parameters, IKey key)
            {
                this.parameters = parameters;
                this.sigParams = GetSigKeyParams(key);
            }

            internal SignerProvider(SignatureParameters parameters, ICipherParameters sigParams)
            {
                this.parameters = parameters;
                this.sigParams = sigParams;
            }

            public ISigner CreateEngine(EngineUsage usage)
            {
                ISigner sig;

                if (parameters.Algorithm.Mode == AlgorithmMode.PKCSv1_5)
                {
                    sig = new RsaDigestSigner(ENGINE_PROVIDER.CreateEngine(usage), FipsShs.CreateDigest(parameters.DigestAlgorithm));
                }
                else
                {
                    sig = new X931Signer(ENGINE_PROVIDER.CreateEngine(usage), FipsShs.CreateDigest(parameters.DigestAlgorithm), false);
                }

                sig.Init((usage == EngineUsage.SIGNING), sigParams);

                return sig;
            }
        }

        internal class PssSignerProvider : IEngineProvider<ISigner>
        {
            private readonly PssSignatureParameters parameters;
            private readonly ICipherParameters sigParams;

            internal PssSignerProvider(PssSignatureParameters parameters, IKey key)
            {
                this.parameters = parameters;
                this.sigParams = GetSigKeyParams(key);
            }

            internal PssSignerProvider(PssSignatureParameters parameters, ICipherParameters sigParams)
            {
                this.parameters = parameters;
                this.sigParams = sigParams;
            }

            public ISigner CreateEngine(EngineUsage usage)
            {
                ISigner sig = new PssSigner(ENGINE_PROVIDER.CreateEngine(usage), FipsShs.CreateDigest(parameters.DigestAlgorithm), parameters.SaltLength, parameters.GetSalt());

                sig.Init((usage == EngineUsage.SIGNING), sigParams);

                return sig;
            }
        }

        private static void CheckKeyUsage(AsymmetricRsaKey key, AsymmetricRsaKey.Usage usage)
        {
            // FSM_STATE:5.12,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!key.CanBeUsed(usage))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                if (usage == AsymmetricRsaKey.Usage.SignOrVerify)
                {
                    throw new IllegalKeyException("attempt to sign/verify with RSA modulus already used for encrypt/decrypt");
                }
                else
                {
                    throw new IllegalKeyException("attempt to encrypt/decrypt with RSA modulus already used for sign/verify");
                }
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"
        }

        internal static RsaKeyParameters GetPublicKeyParameters(AsymmetricRsaPublicKey k, AsymmetricRsaKey.Usage usage)
        {
            CheckKeyUsage(k, usage);

            return new RsaKeyParameters(false, k.Modulus, k.PublicExponent);
        }

        internal static RsaKeyParameters GetPrivateKeyParameters(AsymmetricRsaPrivateKey k, AsymmetricRsaKey.Usage usage)
        {
            CheckKeyUsage(k, usage);

            if (k.PublicExponent.Equals(BigInteger.Zero))
            {
                return new RsaKeyParameters(true, k.Modulus, k.PrivateExponent);
            }
            else
            {
                return new RsaPrivateCrtKeyParameters(k.Modulus, k.PublicExponent, k.PrivateExponent, k.P, k.Q, k.DP, k.DQ, k.QInv);
            }
        }

        internal class EngineProvider : IEngineProvider<RsaBlindedEngine>
        {
            public RsaBlindedEngine CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Alg, new RsaBlindedEngine(), new RsaEngineTest());
            }
        }

        internal class RsaEngineTest : VariantKatTest<RsaBlindedEngine>
        {
            private readonly BigInteger mod = new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16);
            private readonly BigInteger pubExp = new BigInteger("11", 16);
            private readonly BigInteger privExp = new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16);
            private readonly BigInteger p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
            private readonly BigInteger q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);
            private readonly BigInteger pExp = new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16);
            private readonly BigInteger qExp = new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16);
            private readonly BigInteger crtCoef = new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16);

            //
            // to check that we handling byte extension by big number correctly.
            //
            private readonly byte[] edgeInput = Hex.Decode("ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
            private readonly byte[] edgeOutput = Hex.Decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc3497a9fb17ba03d95f28fad91247d6f8ebc463fa8ada974f0f4e28961565a73a46a465369e0798ccbf7893cb9afaa7c426cc4fea6f429e67b6205b682a9831337f2548fd165c2dd7bf5b54be5894403d6e9f6283e65fb134cd4687bf86f95e7a");

            internal override void Evaluate(RsaBlindedEngine rsaEngine)
            {
                RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
                RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
                byte[] data = edgeInput;

                rsaEngine.Init(true, new ParametersWithRandom(pubParameters, Utils.testRandom));

                try
                {
                    data = rsaEngine.ProcessBlock(data, 0, data.Length);
                }
                catch (Exception e)
                {
                    Fail("Self test failed: exception " + e.Message);
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.RsaStartupRawEnc], data))
                {
                    Fail("Self test failed: input does not match decrypted output");
                }

                rsaEngine.Init(false, new ParametersWithRandom(privParameters, Utils.testRandom));

                try
                {
                    data = rsaEngine.ProcessBlock(data, 0, data.Length);
                }
                catch (Exception e)
                {
                    Fail("Self test failed: exception " + e.Message);
                }

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.RsaStartupRawDec], data))
                {
                    Fail("Self test failed: input does not match decrypted output");
                }
            }
        }

        private static void rsaSignTest(IEngineProvider<RsaBlindedEngine> provider)
        {
            SelfTestExecutor.Validate(Pkcs1v15.Algorithm, new RsaSignTest(provider));
        }

        private class RsaSignTest : VariantInternalKatTest
        {
            private readonly IEngineProvider<RsaBlindedEngine> provider;

            internal RsaSignTest(IEngineProvider<RsaBlindedEngine> provider) : base(Pkcs1v15.Algorithm)
            {
                this.provider = provider;
            }

            internal override void Evaluate()
            {
                RsaDigestSigner signer = new RsaDigestSigner(provider.CreateEngine(EngineUsage.GENERAL), FipsShs.CreateDigest(FipsShs.Sha256));

                signer.Init(false, new RsaKeyParameters(false, katM, katE));

                signer.BlockUpdate(msg, 0, msg.Length);

                if (!signer.VerifySignature(FipsKats.Values[FipsKats.Vec.RsaStartupVerifySig]))
                {
                    Fail("self test signature verify failed.");
                }

                signer.Init(true, new ParametersWithRandom(testPrivKey, Utils.testRandom));

                signer.BlockUpdate(msg, 0, msg.Length);

                byte[] sig = signer.GenerateSignature();

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.RsaStartupResultSig], sig))
                {
                    Fail("self test signature generate failed.");
                }
            }
        }

        private static void rsaKeyTransportTest(IEngineProvider<RsaBlindedEngine> provider)
        {
            SelfTestExecutor.Validate(WrapOaep.Algorithm, new RsaOaepKeyTransportTest(provider));
        }

        private class RsaOaepKeyTransportTest : VariantInternalKatTest
        {
            private readonly IEngineProvider<RsaBlindedEngine> provider;

            internal RsaOaepKeyTransportTest(IEngineProvider<RsaBlindedEngine> provider) : base(WrapOaep.Algorithm)
            {
                this.provider = provider;
            }

            internal override void Evaluate()
            {
                byte[] oaepOut = Hex.Decode(
                    "4458cce0f94ebd79d275a134d224f95ef4126034e5d979359703b466096fcc15b71b78df4d4a68033112dfcfad7611cc" +
                        "0458475ab4a66b815f87fcb16a8aa1133441b9d61ed846c4856c5d42059fab7505bd8ffa5281a2bb187c6c853f298c98" +
                        "d5752a40be905f85e5ccb27d59415f09ac12a1788d654c675d98f412e6481e6f1159f1736dd96b29c99b411b4e5420b5" +
                        "6b07be2885dbc397fa091f66877c41e502cb4afeba460a2ebcdec7d09d933e630b98a4510ad6f32ca7ffc1bdb43e46ff" +
                        "f709819d3a69d9b62b774cb12c9dc176a6911bf370ab5029719dc1b4c13e23e57e46a7cd8ba5ee54c954ed460835ddab" +
                        "0086fa36ac110a5790e82c929bc7ca86");

                IAsymmetricBlockCipher cipher = new OaepEncoding(provider.CreateEngine(EngineUsage.GENERAL), new Sha1Digest(), new Sha1Digest(), null);

                cipher.Init(true, new ParametersWithRandom(testPubKey, new TestRandomData("18b776ea21069d69776a33e96bad48e1dda0a5ef")));

                byte[] output;

                output = cipher.ProcessBlock(msg, 0, msg.Length);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.RsaStartupOaepEnc], output))
                {
                    Fail("self test OAEP transport encrypt failed.");
                }

                cipher.Init(false, new ParametersWithRandom(testPrivKey, Utils.testRandom));

                output = cipher.ProcessBlock(oaepOut, 0, oaepOut.Length);

                if (!Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.RsaStartupOaepDec], output))
                {
                    Fail("self test OAEP transport decrypt failed.");
                }
            }
        }
    }
}

