using System;

using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using NewHopeImpl = Org.BouncyCastle.Crypto.Internal.Agreement.NewHope;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for the PQC key-exchange algorithm NewHope
    /// </summary>
    public class NewHope
    {
        /// <summary>
        /// Raw NewHope algorithm marker.
        /// </summary>
        public static readonly GeneralAlgorithm Alg = new GeneralAlgorithm("NewHope");

        /// <summary>
        /// Perform key exchange calculations using SHA3_256 to process the result.
        /// </summary>
        public static readonly Parameters Sha3_256 = new Parameters(FipsShs.Sha3_256);

        /// <summary>
        /// Service generator handle for NewHope key pair generation.
        /// </summary>
        public static readonly KeyGenerationParameters KeyGen = new KeyGenerationParameters();

        private NewHope()
        {
        }

        /// <summary>
        /// Base class for the NewHope key exchange parameters.
        /// </summary>
        public class Parameters : Parameters<GeneralAlgorithm>, IGenerationServiceType<IExchangePairGeneratorService>, IGenerationService<IExchangePairGeneratorService>
        {
            internal Parameters(DigestAlgorithm digestAlgorithm): base(Alg)
            {

            }

            Func<IParameters<Algorithm>, SecureRandom, IExchangePairGeneratorService> IGenerationService<IExchangePairGeneratorService>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new PublicKeyNHService(parameters as Parameters, random);
            }

            private class PublicKeyNHService : IExchangePairGeneratorService
            {
                private readonly Parameters parameters;
                private readonly SecureRandom random;

                public PublicKeyNHService(Parameters parameters, SecureRandom random)
                {
                    this.parameters = parameters;
                    this.random = random;
                }

                public ExchangePair GenerateExchange(IAsymmetricPublicKey otherKey)
                {
                    General.Utils.ApprovedModeCheck("generator", Alg);

                    byte[] ourSharedKey = new byte[NewHopeImpl.AgreementSize];
                    byte[] ourSend = new byte[NewHopeImpl.SendBBytes];

                    AsymmetricNHPublicKey publicKey = (AsymmetricNHPublicKey)otherKey;

                    NewHopeImpl.SharedB(random, ourSharedKey, ourSend, publicKey.GetKeyData());

                    return new ExchangePair(new AsymmetricNHPublicKey(ourSend), ourSharedKey);
                }
            }
        }

        /// <summary>
        /// Parameters for NewHope key pair generation.
        /// </summary>
        public class KeyGenerationParameters : Parameters<GeneralAlgorithm>, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
        {
            internal KeyGenerationParameters(): base(Alg)
            {

            }

            Func<IParameters<Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
            {
                General.Utils.ApprovedModeCheck("generator", Alg);

                return (parameter, random) => new KeyPairGenerator(parameter as KeyGenerationParameters, random);
            }
        }

        /// <summary>
        /// Base class for NewHope key pair generation.
        /// </summary>
        public class KeyPairGenerator : AsymmetricKeyPairGenerator<KeyGenerationParameters, AsymmetricNHPublicKey, AsymmetricNHPrivateKey>
        {
            private readonly SecureRandom random;

            internal KeyPairGenerator(KeyGenerationParameters kgenParams, SecureRandom random) : base(kgenParams)
            {
                this.random = random;
            }

            public override AsymmetricKeyPair<AsymmetricNHPublicKey, AsymmetricNHPrivateKey> GenerateKeyPair()
            {
                General.Utils.ApprovedModeCheck("generator", Alg);

                byte[] send = new byte[NewHopeImpl.SendABytes];
                ushort[] secret = new ushort[NewHopeImpl.PolySize];

                NewHopeImpl.KeyGen(random, send, secret);

                return new AsymmetricKeyPair<AsymmetricNHPublicKey, AsymmetricNHPrivateKey>(
                                new AsymmetricNHPublicKey(send), new AsymmetricNHPrivateKey(secret));
            }
        }
    }
}
