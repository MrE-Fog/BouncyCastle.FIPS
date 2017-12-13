using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Encodings;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.General
{
    public class Rsa
    {
        private Rsa()
        {

        }

        public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm(FipsRsa.Alg.Name);

        /// <summary>
        ///  RSA PKCS#1.5 key wrap algorithm parameter source.
        /// </summary>
        public static readonly Pkcs1v15WrapParameters WrapPkcs1v15 = new Pkcs1v15WrapParameters();

        /// <summary>
        /// Parameters for use with PKCS#1 v1.5 formatted key wrapping/unwrapping and encryption/decryption.
        /// </summary>
        public class Pkcs1v15WrapParameters : Parameters<GeneralAlgorithm>
        {
            internal Pkcs1v15WrapParameters() : base(new GeneralAlgorithm(Alg, AlgorithmMode.PKCSv1_5))
            {
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
                if (key is KeyWithRandom)
                {
                    this.unwrapper = createCipher(false, (IAsymmetricKey)((KeyWithRandom)key).Key, algorithmDetails, ((KeyWithRandom)key).Random);
                }
                else
                {
                    this.unwrapper = createCipher(false, (IAsymmetricKey)key, algorithmDetails, null);
                }
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
            IAsymmetricBlockCipher engine = FipsRsa.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);

            ICipherParameters lwParams;

            if (key is AsymmetricRsaPublicKey)
            {
                AsymmetricRsaPublicKey k = (AsymmetricRsaPublicKey)key;

                lwParams = FipsRsa.GetPublicKeyParameters(k, AsymmetricRsaKey.Usage.EncryptOrDecrypt);
            }
            else
            {
                AsymmetricRsaPrivateKey k = (AsymmetricRsaPrivateKey)key;

                lwParams = FipsRsa.GetPrivateKeyParameters(k, AsymmetricRsaKey.Usage.EncryptOrDecrypt);
            }

            if (parameters.Algorithm.Equals(WrapPkcs1v15.Algorithm))
            {
                engine = new Pkcs1Encoding(engine);
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
