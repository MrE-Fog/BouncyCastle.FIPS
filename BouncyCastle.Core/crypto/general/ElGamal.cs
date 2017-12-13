using System;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Encodings;
using Org.BouncyCastle.Crypto.Internal.Engines;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Internal.Generators;

namespace Org.BouncyCastle.Crypto.General
{
    public class ElGamal
    {
        private ElGamal()
        {

        }

        public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm("ELGAMAL");

        /// <summary>
        ///  ElGamal OAEP key wrap algorithm parameter source - default is SHA-384
        /// </summary>
        public static readonly OaepWrapParameters WrapOaep = new OaepWrapParameters(new GeneralAlgorithm(Alg, AlgorithmMode.OAEP), FipsShs.Sha384);

        /// <summary>
        ///  ElGamal PKCS#1.5 key wrap algorithm parameter source.
        /// </summary>
        public static readonly Pkcs1v15WrapParameters WrapPkcs1v15 = new Pkcs1v15WrapParameters();

        /// <summary>
        /// OAEP key wrap parameters base class.
        /// </summary>
        public class OaepWrapParameters : OaepParameters<OaepWrapParameters, GeneralAlgorithm, DigestAlgorithm>
        {
            internal OaepWrapParameters(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm) : base(algorithm, digestAlgorithm, digestAlgorithm, null)
            {
            }

            internal OaepWrapParameters(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm, DigestAlgorithm mgfAlgorithm, byte[] encodedParams) : base(algorithm, digestAlgorithm, mgfAlgorithm, encodedParams)
            {
            }

            internal override OaepWrapParameters CreateParameter(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm, DigestAlgorithm mgfAlgorithm, byte[] encodedParams)
            {
                return new OaepWrapParameters(algorithm, digestAlgorithm, mgfAlgorithm, encodedParams);
            }
        }

        /// <summary>
        /// Parameters for use with PKCS#1 v1.5 formatted key wrapping/unwrapping and encryption/decryption.
        /// </summary>
        public class Pkcs1v15WrapParameters : Parameters<GeneralAlgorithm>
        {
            internal Pkcs1v15WrapParameters() : base(new GeneralAlgorithm(Alg, AlgorithmMode.PKCSv1_5))
            {
            }
        }

        /// <summary>
        /// ElGamal key pair generation parameters.
        /// </summary>
        public class KeyGenerationParameters : Parameters<GeneralAlgorithm>, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
        {
            private DHDomainParameters domainParameters;

            /**
             * Base constructor for specific domain parameters.
             *
             * @param domainParameters the DH domain parameters.
             */
            public KeyGenerationParameters(DHDomainParameters domainParameters) : base(Alg)
            {
                this.domainParameters = domainParameters;
            }

            /**
             * Constructor for specifying the ElGamal algorithm explicitly.
             *
             * @param parameters the particular parameter set to generate keys for.
             * @param domainParameters DH domain parameters representing the curve any generated keys will be for.
             */
            private KeyGenerationParameters(Parameters<GeneralAlgorithm> parameters, DHDomainParameters domainParameters) : base(parameters.Algorithm)
            {
                this.domainParameters = domainParameters;
            }

            public KeyGenerationParameters For(Parameters<GeneralAlgorithm> parameters)
            {
                return new KeyGenerationParameters(parameters, DomainParameters);
            }

            public DHDomainParameters DomainParameters
            {
                get
                {
                    return domainParameters;
                }
            }

            Func<IParameters<Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyPairGenerator(parameters as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// ElGamal key pair generator class.
        /// </summary>
        public class KeyPairGenerator : AsymmetricKeyPairGenerator<KeyGenerationParameters, AsymmetricDHPublicKey, AsymmetricDHPrivateKey>
        {
            private readonly DHKeyPairGenerator engine = new DHKeyPairGenerator();
            private readonly DHDomainParameters domainParameters;
            private readonly DHKeyGenerationParameters param;

            internal KeyPairGenerator(KeyGenerationParameters keyGenParameters, SecureRandom random) : base(keyGenParameters)
            {

                this.param = new DHKeyGenerationParameters(random, getDomainParams(keyGenParameters.DomainParameters));
                this.domainParameters = keyGenParameters.DomainParameters;
                this.engine.Init(param);
            }

            public override AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey> GenerateKeyPair()
            {
                Utils.ApprovedModeCheck("generator", Alg);

                AsymmetricCipherKeyPair kp = engine.GenerateKeyPair();

                AsymmetricDHPublicKey pubK = new AsymmetricDHPublicKey(Parameters.Algorithm, domainParameters, ((ElGamalPublicKeyParameters)kp.Public).Y);
                AsymmetricDHPrivateKey priK = new AsymmetricDHPrivateKey(Parameters.Algorithm, domainParameters, ((ElGamalPrivateKeyParameters)kp.Private).X);

                return new AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey>(pubK, priK);
            }
        }

        private static DHParameters getDomainParams(DHDomainParameters dhParameters)
        {
            return new DHParameters(dhParameters.P, dhParameters.G, dhParameters.Q, dhParameters.M, dhParameters.L, dhParameters.J, null);
        }

        internal class OaepKeyWrapper : IKeyWrapper<OaepWrapParameters>
        {
            private readonly OaepWrapParameters algorithmDetails;
            private readonly IAsymmetricBlockCipher wrapper;

            internal OaepKeyWrapper(OaepWrapParameters algorithmDetails, IKey key)
            {
                this.algorithmDetails = algorithmDetails;

                if (key is KeyWithRandom)
                {
                    this.wrapper = createCipher(true, (IAsymmetricKey)((KeyWithRandom)key).Key, algorithmDetails, ((KeyWithRandom)key).Random);
                }
                else
                {
                    this.wrapper = createCipher(true, (IAsymmetricKey)key, algorithmDetails, null);
                }
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
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    throw new CryptoUnapprovedOperationError("attempt to create unapproved unwrapper in approved only mode");
                }

                return new SimpleBlockResult(wrapper.ProcessBlock(keyData, 0, keyData.Length));
            }
        }

        internal class OaepKeyUnwrapper : IKeyUnwrapper<OaepWrapParameters>
        {
            private readonly OaepWrapParameters algorithmDetails;
            private readonly IAsymmetricBlockCipher unwrapper;

            internal OaepKeyUnwrapper(OaepWrapParameters algorithmDetails, IKey key)
            {
                this.algorithmDetails = algorithmDetails;
                this.unwrapper = createCipher(false, (IAsymmetricKey)key, algorithmDetails, null);
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
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    throw new CryptoUnapprovedOperationError("attempt to create unapproved unwrapper in approved only mode");
                }

                return new SimpleBlockResult(unwrapper.ProcessBlock(cipherText, offset, length));
            }
        }

        internal class Pkcs1v15KeyWrapper : IKeyWrapper<Pkcs1v15WrapParameters>
        {
            private readonly Pkcs1v15WrapParameters algorithmDetails;
            private readonly IAsymmetricBlockCipher wrapper;

            internal Pkcs1v15KeyWrapper(Pkcs1v15WrapParameters algorithmDetails, IKey key)
            {
                this.algorithmDetails = algorithmDetails;
                if (key is KeyWithRandom)
                {
                    this.wrapper = createCipher(true, (IAsymmetricKey)((KeyWithRandom)key).Key, algorithmDetails, ((KeyWithRandom)key).Random);
                }
                else
                {
                    this.wrapper = createCipher(true, (IAsymmetricKey)key, algorithmDetails, null);
                }
            }

            public Pkcs1v15WrapParameters AlgorithmDetails
            {
                get
                {
                    return algorithmDetails;
                }
            }

            public IBlockResult Wrap(byte[] keyData)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    throw new CryptoUnapprovedOperationError("attempt to create unapproved unwrapper in approved only mode");
                }

                return new SimpleBlockResult(wrapper.ProcessBlock(keyData, 0, keyData.Length));
            }
        }

        internal class Pkcs1v15KeyUnwrapper : IKeyUnwrapper<Pkcs1v15WrapParameters>
        {
            private readonly Pkcs1v15WrapParameters algorithmDetails;
            private readonly IAsymmetricBlockCipher unwrapper;

            internal Pkcs1v15KeyUnwrapper(Pkcs1v15WrapParameters algorithmDetails, IKey key)
            {
                this.algorithmDetails = algorithmDetails;
                this.unwrapper = createCipher(false, (IAsymmetricKey)key, algorithmDetails, null);
            }

            public Pkcs1v15WrapParameters AlgorithmDetails
            {
                get
                {
                    return algorithmDetails;
                }
            }

            public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
            {
                if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
                {
                    throw new CryptoUnapprovedOperationError("attempt to create unapproved unwrapper in approved only mode");
                }

                return new SimpleBlockResult(unwrapper.ProcessBlock(cipherText, offset, length));
            }
        }

        private static IAsymmetricBlockCipher createCipher(bool forEncryption, IAsymmetricKey key, IParameters<Algorithm> parameters, SecureRandom random)
        {
            IAsymmetricBlockCipher engine = new ElGamalEngine();

            ICipherParameters lwParams;

            if (key is AsymmetricDHPublicKey)
            {
                AsymmetricDHPublicKey k = (AsymmetricDHPublicKey)key;

                lwParams = new ElGamalPublicKeyParameters(k.Y, new DHParameters(k.DomainParameters.P, k.DomainParameters.G, k.DomainParameters.Q, k.DomainParameters.L));
            }
            else
            {
                AsymmetricDHPrivateKey k = (AsymmetricDHPrivateKey)key;

                lwParams = new ElGamalPrivateKeyParameters(k.X, new DHParameters(k.DomainParameters.P, k.DomainParameters.G, k.DomainParameters.Q, k.DomainParameters.L));
            }

            if (parameters.Algorithm.Equals(WrapPkcs1v15.Algorithm))
            {
                engine = new Pkcs1Encoding(engine);
            }
            else if (parameters.Algorithm.Equals(WrapOaep.Algorithm))
            {
                OaepWrapParameters oeapParams = (OaepWrapParameters)parameters;

                engine = new OaepEncoding(engine, FipsShs.CreateDigest(oeapParams.DigestAlgorithm), FipsShs.CreateDigest(oeapParams.MgfDigestAlgorithm), oeapParams.GetEncodingParams());
            }

            if (random != null)
            {
                lwParams = new ParametersWithRandom(lwParams, random);
            }

            engine.Init(forEncryption, lwParams);

            return engine;
        }
    }
}
