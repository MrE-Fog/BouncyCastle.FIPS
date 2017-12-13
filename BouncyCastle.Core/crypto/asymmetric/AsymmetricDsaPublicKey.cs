using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPublicKeyDsaService : IVerifierFactoryService
    {

    }

    /// <summary>
    /// Class for Digital Signature Algorithm (DSA) public keys.
    /// </summary>
    public class AsymmetricDsaPublicKey
        : AsymmetricDsaKey, IAsymmetricPublicKey, ICryptoServiceType<IPublicKeyDsaService>, IServiceProvider<IPublicKeyDsaService>
    {
		private BigInteger y;

		public AsymmetricDsaPublicKey(Algorithm algorithm, DsaDomainParameters parameters, BigInteger y)
            : base(algorithm, parameters)
		{
			this.y = KeyUtils.Validated(parameters, y);
		}

        /// <summary>
        /// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing a DSA public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="enc">An encoding of a SubjectPublicKeyInfo object.</param>
        public AsymmetricDsaPublicKey(Algorithm algorithm, byte[] enc)
            : this(algorithm, SubjectPublicKeyInfo.GetInstance(enc))
		{
		}

        /// <summary>
        /// Constructor from an algorithm and a SubjectPublicKeyInfo object containing a DSA public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricDsaPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
            : base(algorithm, publicKeyInfo.AlgorithmID)
		{
			this.y = KeyUtils.Validated(DomainParameters, ParsePublicKey(publicKeyInfo));
		}

		private static BigInteger ParsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
		{
			DerInteger derY;

			try
			{
				derY = DerInteger.GetInstance(publicKeyInfo.GetPublicKey());
			}
			catch (Exception e)
			{
				throw new ArgumentException("invalid info structure in DSA public key: " + e.Message, e);
			}

			return derY.Value;
		}

        /// <summary>
        /// Return the public value Y.
        /// </summary>
		public virtual BigInteger Y
		{
			get { return y; }
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
		{
			DsaDomainParameters domainParameters = this.DomainParameters;

			if (DomainParameters == null)
			{
				return KeyUtils.GetEncodedSubjectPublicKeyInfo(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa), new DerInteger(y));
			}

			return KeyUtils.GetEncodedSubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa,
                    new DsaParameter(domainParameters.P, domainParameters.Q, domainParameters.G).ToAsn1Object()),
                new DerInteger(y));
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			if (!(o is AsymmetricDsaPublicKey))
			{
				return false;
			}

			AsymmetricDsaPublicKey other = (AsymmetricDsaPublicKey)o;

			return y.Equals(other.y) && this.DomainParameters.Equals(other.DomainParameters);
		}

		public override int GetHashCode()
		{
			int result = y.GetHashCode();
			result = 31 * result + this.DomainParameters.GetHashCode();
			return result;
		}

        Func<IKey, IPublicKeyDsaService> IServiceProvider<IPublicKeyDsaService>.GetFunc(SecurityContext context)
        {
            return (key) => new PublicKeyDsaService(key);
        }

        private class PublicKeyDsaService : IPublicKeyDsaService
        {
            private readonly AsymmetricDsaPublicKey publicKey;

            public PublicKeyDsaService(IKey publicKey)
            {
                this.publicKey = (AsymmetricDsaPublicKey)publicKey;
            }

            public IVerifierFactory<A> CreateVerifierFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                if (algorithmDetails is Fips.FipsDsa.SignatureParameters)
                {
                    return (IVerifierFactory<A>)new VerifierFactory<Fips.FipsDsa.SignatureParameters>(algorithmDetails as Fips.FipsDsa.SignatureParameters, new Fips.FipsDsa.SignerProvider(algorithmDetails as Fips.FipsDsa.SignatureParameters, publicKey));
                }
                else
                {
                    General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                    return (IVerifierFactory<A>)new VerifierFactory<General.Dsa.SignatureParameters>(algorithmDetails as General.Dsa.SignatureParameters, new General.Dsa.SignerProvider(algorithmDetails as General.Dsa.SignatureParameters, publicKey));
                }
            }
        }
    }
}

