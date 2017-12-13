using System;

using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Signers;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for non-FIPS implementations of DSA based algorithms.
    /// </summary>
	public class Dsa
	{
        public static readonly Algorithm Alg = FipsDsa.Alg;

        public static readonly SignatureParameters DDsa = new SignatureParameters (new GeneralAlgorithm (FipsDsa.Alg, AlgorithmMode.DDSA), FipsShs.Sha384);

        public class SignatureParameters: SignatureParameters<SignatureParameters, GeneralAlgorithm, DigestAlgorithm>
		{
			internal SignatureParameters(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm): base(algorithm, digestAlgorithm)
			{
			}

			internal override SignatureParameters CreateParameter(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm)
			{
				return new SignatureParameters (algorithm, digestAlgorithm);
			}
		}

        private Dsa()
        {
        }

        private static ICipherParameters GetPrivateParameters(IKey key)
        {
            DsaPrivateKeyParameters privateKeyParameters;
            SecureRandom random;

            if (key is KeyWithRandom)
            {
                KeyWithRandom k = (KeyWithRandom)key;

                privateKeyParameters = GetPrivateKeyParameters((AsymmetricDsaPrivateKey)k.Key);
                random = k.Random;
            }
            else
            {
                privateKeyParameters = GetPrivateKeyParameters((AsymmetricDsaPrivateKey)key);
                random = CryptoServicesRegistrar.GetSecureRandom();
            }

            return new ParametersWithRandom(privateKeyParameters, random);
        }

        internal class SignerProvider : IEngineProvider<ISigner>
        {
            private readonly SignatureParameters parameters;
            private readonly ICipherParameters sigParams;

            internal SignerProvider(SignatureParameters parameters, IKey key)
            {
                this.parameters = parameters;
                if (key is AsymmetricDsaPublicKey)
                {
                    AsymmetricDsaPublicKey dsaPublicKey = (AsymmetricDsaPublicKey)key;

                    this.sigParams = new DsaPublicKeyParameters(dsaPublicKey.Y, getDomainParams(dsaPublicKey.DomainParameters));
                }
                else
                {
                    this.sigParams = GetPrivateParameters(key);
                }
            }

            internal SignerProvider(SignatureParameters parameters, ICipherParameters sigParams)
            {
                this.parameters = parameters;
                this.sigParams = sigParams;
            }

            public ISigner CreateEngine(EngineUsage usage)
            {
                ISigner sig = new DsaDigestSigner(new DsaSigner(new HMacDsaKCalculator(FipsShs.CreateHmac(parameters.DigestAlgorithm))), FipsShs.CreateDigest(parameters.DigestAlgorithm));

                sig.Init((usage == EngineUsage.SIGNING), sigParams);

                return sig;
            }
        }

        private static DsaParameters getDomainParams(DsaDomainParameters dsaParams)
        {
            return new DsaParameters(dsaParams.P, dsaParams.Q, dsaParams.G);
        }

        private static DsaPrivateKeyParameters GetPrivateKeyParameters(AsymmetricDsaPrivateKey privKey)
        {
            return new DsaPrivateKeyParameters(privKey.X, getDomainParams(privKey.DomainParameters));
        }
    }
}

