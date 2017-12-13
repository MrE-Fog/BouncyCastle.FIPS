using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeyECService : ISignatureFactoryService, IAgreementCalculatorService
    {

    }

    public class AsymmetricECPrivateKey: AsymmetricECKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeyECService>, IServiceProvider<IPrivateKeyECService>
    {
		private readonly int        hashCode;
		private readonly byte[]     publicKey;

		private BigInteger d;

		public AsymmetricECPrivateKey(Algorithm ecAlg, IECDomainParametersID domainParametersID, BigInteger s): this(ecAlg, domainParametersID, s, null)
		{
		}

		public AsymmetricECPrivateKey(Algorithm ecAlg, ECDomainParameters domainParameters, BigInteger s): this(ecAlg, domainParameters, s, null)
		{
		}

		public AsymmetricECPrivateKey(Algorithm ecAlg, ECDomainParameters domainParameters, BigInteger s, ECPoint w): base(ecAlg, domainParameters)
		{
			this.d = s;
			this.publicKey = extractPublicKeyBytes(w);
			this.hashCode = calculateHashCode();
		}

		public AsymmetricECPrivateKey(Algorithm ecAlg, IECDomainParametersID domainParametersID, BigInteger s, ECPoint w): base(ecAlg, domainParametersID)
		{
			this.d = s;
			this.publicKey = extractPublicKeyBytes(w);
			this.hashCode = calculateHashCode();
		}

        /// <summary>
        /// Constructor from an algorithm and an encoding of a PrivateKeyInfo object containing an EC private key.
        /// </summary>
        /// <param name="ecAlg">Algorithm marker to associate with the key.</param>
        /// <param name="encoding">An encoding of a PrivateKeyInfo object.</param>
        public AsymmetricECPrivateKey(Algorithm ecAlg, byte[] encoding): this(ecAlg, PrivateKeyInfo.GetInstance(encoding))
		{
		}

        /// <summary>
        /// Constructor from an algorithm and a PrivateKeyInfo object containing an EC private key.
        /// </summary>
        /// <param name="ecAlg">Algorithm marker to associate with the key.</param>
        /// <param name="privateKeyInfo">A PrivateKeyInfo object.</param>
        public AsymmetricECPrivateKey(Algorithm ecAlg, PrivateKeyInfo privateKeyInfo): this(ecAlg, privateKeyInfo.PrivateKeyAlgorithm, parsePrivateKey(privateKeyInfo))
		{
		}

		private AsymmetricECPrivateKey(Algorithm ecAlg, AlgorithmIdentifier algorithmIdentifier, ECPrivateKeyStructure privateKey): base(ecAlg, algorithmIdentifier)
		{
			this.d = privateKey.GetKey();
			DerBitString wEnc = privateKey.GetPublicKey();
			// really this should be getOctets() but there are keys with padbits out in the wild
			this.publicKey = (wEnc == null) ? null : wEnc.GetBytes();
			this.hashCode = calculateHashCode();
		}

		private static ECPrivateKeyStructure parsePrivateKey(PrivateKeyInfo privateKeyInfo)
		{
			try
			{
				return ECPrivateKeyStructure.GetInstance(privateKeyInfo.ParsePrivateKey());
			}
			catch (IOException e)
			{
				throw new ArgumentException("Unable to parse EC private key: " + e.Message, e);
			}
		}

		private byte[] extractPublicKeyBytes(ECPoint w)
		{
			CheckApprovedOnlyModeStatus();

			if (w == null)
			{
				return null;
			}

			return Asn1OctetString.GetInstance(new X9ECPoint(w).ToAsn1Object()).GetOctets();
		}

		public override byte[] GetEncoded()
		{
			CheckApprovedOnlyModeStatus();

			//KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

			X962Parameters parameters = KeyUtils.BuildCurveParameters(this.DomainParameters);
			int            orderBitLength = KeyUtils.GetOrderBitLength(this.DomainParameters);

			ECPrivateKeyStructure keyStructure;

			if (publicKey != null)
			{
				keyStructure = new ECPrivateKeyStructure(orderBitLength, this.S, new DerBitString(publicKey), parameters);
			}
			else
			{
				keyStructure = new ECPrivateKeyStructure(orderBitLength, this.S, parameters);
			}

			return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, parameters), keyStructure);
		}

		public BigInteger S
		{
			get {
			CheckApprovedOnlyModeStatus();

			//KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

			return d;
		}
		}
			
		public override bool Equals(object o)
		{
			CheckApprovedOnlyModeStatus();

			if (this == o)
			{
				return true;
			}

			if (!(o is AsymmetricECPrivateKey))
			{
				return false;
			}

			AsymmetricECPrivateKey other = (AsymmetricECPrivateKey)o;

			if (!d.Equals(other.d))
			{
				return false;
			}

			// we ignore the public point encoding.

			return this.DomainParameters.Equals(other.DomainParameters);
		}

		public override int GetHashCode()
		{
			CheckApprovedOnlyModeStatus();

			return hashCode;
		}

		private int calculateHashCode()
		{
			int result = d.GetHashCode();
			result = 31 * result + this.DomainParameters.GetHashCode();
			return result;
		}

        Func<IKey, IPrivateKeyECService> IServiceProvider<IPrivateKeyECService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeyECService(key);
        }

        private class PrivateKeyECService : IPrivateKeyECService
        {
            private readonly bool approvedOnlyMode;
            private readonly IKey privateKey;

            public PrivateKeyECService(IKey privateKey)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.privateKey = privateKey;
            }

            public IAgreementCalculator<A> CreateAgreementCalculator<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "EC");

                return (IAgreementCalculator<A>)new FipsEC.AgreementCalculator(algorithmDetails as FipsEC.AgreementParameters, privateKey);
            }

            public ISignatureFactory<A> CreateSignatureFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "EC");

                if (algorithmDetails is Fips.FipsEC.SignatureParameters)
                {
                    return (ISignatureFactory<A>)new SignatureFactory<Fips.FipsEC.SignatureParameters>(algorithmDetails as Fips.FipsEC.SignatureParameters, new Fips.FipsEC.SignerProvider(algorithmDetails as Fips.FipsEC.SignatureParameters, privateKey));
                }
                else
                {
                    General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                    return (ISignatureFactory<A>)new SignatureFactory<General.EC.SignatureParameters>(algorithmDetails as General.EC.SignatureParameters, new General.EC.SignerProvider(algorithmDetails as General.EC.SignatureParameters, privateKey));
                }
            }
        }
    }
}

