using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Signers;
using Org.BouncyCastle.Crypto.Internal.Parameters;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for non-FIPS implementations of Elliptic Curve (EC) based algorithms.
    /// </summary>
    public class EC
	{
        public static readonly Algorithm Alg = FipsEC.Alg;

        public static readonly SignatureParameters DDsa = new SignatureParameters (new GeneralAlgorithm (FipsEC.Alg, AlgorithmMode.DDSA), FipsShs.Sha384);

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

		private EC ()
		{
		}

        private static ICipherParameters GetPublicParameters(IKey key)
        {
            ECPublicKeyParameters publicKeyParameters = GetPublicKeyParameters((AsymmetricECPublicKey)key);

            return publicKeyParameters;
        }

        private static ICipherParameters GetPrivateParameters(IKey key)
        {
            ECPrivateKeyParameters privateKeyParameters;
            SecureRandom random;

            if (key is KeyWithRandom)
            {
                KeyWithRandom k = (KeyWithRandom)key;

                privateKeyParameters = GetPrivateKeyParameters((AsymmetricECPrivateKey)k.Key);
                random = k.Random;
            }
            else
            {
                privateKeyParameters = GetPrivateKeyParameters((AsymmetricECPrivateKey)key);
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
                if (key is AsymmetricECPublicKey)
                {
                    this.sigParams = GetPublicParameters(key);
                }
                else
                {
                    this.sigParams = GetPrivateParameters(key);
                }
            }

            public ISigner CreateEngine(EngineUsage usage)
            {
                ISigner sig = new DsaDigestSigner(new ECDsaSigner(new HMacDsaKCalculator(FipsShs.CreateHmac(parameters.DigestAlgorithm))), FipsShs.CreateDigest(parameters.DigestAlgorithm));

                sig.Init((usage == EngineUsage.SIGNING), sigParams);

                return sig;
            }
        }

        private static Internal.Parameters.EcDomainParameters getDomainParams(Org.BouncyCastle.Crypto.Asymmetric.ECDomainParameters curveParams)
        {
            if (curveParams is NamedECDomainParameters)
            {
                return new Internal.Parameters.ECNamedDomainParameters(((NamedECDomainParameters)curveParams).ID, curveParams.Curve, curveParams.G, curveParams.N, curveParams.H, curveParams.GetSeed());
            }
            return new Internal.Parameters.EcDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H, curveParams.GetSeed());
        }

        private static Internal.Parameters.ECPublicKeyParameters GetPublicKeyParameters(AsymmetricECPublicKey k)
        {
            return new Internal.Parameters.ECPublicKeyParameters(k.W, getDomainParams(k.DomainParameters));
        }

        private static Internal.Parameters.ECPrivateKeyParameters GetPrivateKeyParameters(AsymmetricECPrivateKey k)
        {
            return new Internal.Parameters.ECPrivateKeyParameters(k.S, getDomainParams(k.DomainParameters));
        }
    }
}

