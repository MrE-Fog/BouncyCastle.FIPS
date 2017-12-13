using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPublicKeyECService : IVerifierFactoryService
    {

    }

    /// <summary>
    /// Class for Elliptic Curve (EC) public keys.
    /// </summary>
    public class AsymmetricECPublicKey: AsymmetricECKey, IAsymmetricPublicKey, ICryptoServiceType<IPublicKeyECService>, IServiceProvider<IPublicKeyECService>
    {
		private readonly ECPoint q;

		public AsymmetricECPublicKey(Algorithm ecAlg, IECDomainParametersID domainParameterID, byte[] encodedPoint): base(ecAlg, domainParameterID)
		{
			this.q = KeyUtils.Validated(this.DomainParameters.Curve.DecodePoint(encodedPoint));
		}

		public AsymmetricECPublicKey(Algorithm ecAlg, ECDomainParameters domainParameters, byte[] encodedPoint): base(ecAlg, domainParameters)
		{
			this.q = KeyUtils.Validated(this.DomainParameters.Curve.DecodePoint(encodedPoint));
		}

		public AsymmetricECPublicKey(Algorithm ecAlg, IECDomainParametersID domainParameterID, ECPoint q): base(ecAlg, domainParameterID)
		{
			this.q = KeyUtils.Validated(q);
		}

		public AsymmetricECPublicKey(Algorithm ecAlg, ECDomainParameters domainParameters, ECPoint q): base(ecAlg, domainParameters)
		{
			this.q = KeyUtils.Validated(q);
		}

        /// <summary>
        /// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing an EC public key.
        /// </summary>
        /// <param name="ecAlg">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfoEncoding">An encoding of a SubjectPublicKeyInfo object.</param>
        public AsymmetricECPublicKey(Algorithm ecAlg, byte[] publicKeyInfoEncoding): this(ecAlg, SubjectPublicKeyInfo.GetInstance(publicKeyInfoEncoding))
		{
			
		}

        /// <summary>
        /// Constructor from an algorithm and a SubjectPublicKeyInfo object containing an EC public key.
        /// </summary>
        /// <param name="ecAlg">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricECPublicKey(Algorithm ecAlg, SubjectPublicKeyInfo publicKeyInfo): base(ecAlg, publicKeyInfo.AlgorithmID)
		{
			// really this should be getOctets() but there are keys with padbits out in the wild
			Asn1OctetString key = new DerOctetString(publicKeyInfo.PublicKeyData.GetBytes());
			X9ECPoint derQ = new X9ECPoint(this.DomainParameters.Curve, key);

			this.q = KeyUtils.Validated(derQ.Point);
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
		{
			ECDomainParameters curveParams = this.DomainParameters;
			Asn1Encodable parameters = KeyUtils.BuildCurveParameters(curveParams);

			SubjectPublicKeyInfo info;

			Asn1OctetString p = Asn1OctetString.GetInstance(new X9ECPoint(W).ToAsn1Object());

			info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, parameters), p.GetOctets());

			return KeyUtils.GetEncodedInfo(info);
		}

		public ECPoint W
		{
			get {
				return q;
			}
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			if (!(o is AsymmetricECPublicKey))
			{
				return false;
			}

			AsymmetricECPublicKey other = (AsymmetricECPublicKey)o;

			if (!q.Equals(other.q))
			{
				return false;
			}

			return this.DomainParameters.Equals(other.DomainParameters);
		}

		public override int GetHashCode()
		{
			int result = q.GetHashCode();
			result = 31 * result + this.DomainParameters.GetHashCode();
			return result;
		}

        Func<IKey, IPublicKeyECService> IServiceProvider<IPublicKeyECService>.GetFunc(SecurityContext context)
        {
            return (key) => new PublicKeyECService(key);
        }

        private class PublicKeyECService : IPublicKeyECService
        {
            private readonly AsymmetricECPublicKey publicKey;

            public PublicKeyECService(IKey publicKey)
            {
                this.publicKey = (AsymmetricECPublicKey)publicKey;
            }

            public IVerifierFactory<A> CreateVerifierFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                if (algorithmDetails is Fips.FipsEC.SignatureParameters)
                {
                    return (IVerifierFactory<A>)new VerifierFactory<Fips.FipsEC.SignatureParameters>(algorithmDetails as Fips.FipsEC.SignatureParameters, new Fips.FipsEC.SignerProvider(algorithmDetails as Fips.FipsEC.SignatureParameters, publicKey));
                }
                else
                {
                    General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                    return (IVerifierFactory<A>)new VerifierFactory<General.EC.SignatureParameters>(algorithmDetails as General.EC.SignatureParameters, new General.EC.SignerProvider(algorithmDetails as General.EC.SignatureParameters, publicKey));
                }
            }
        }
    }
}

