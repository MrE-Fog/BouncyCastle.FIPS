using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPublicKeyRsaService : IKeyWrappingService, IVerifierFactoryService
    {

    }

    /// <summary>
    /// Class for RSA public keys.
    /// </summary>
    public class AsymmetricRsaPublicKey
        : AsymmetricRsaKey, IAsymmetricPublicKey, ICryptoServiceType<IPublicKeyRsaService>, IServiceProvider<IPublicKeyRsaService>
    {
		private readonly BigInteger publicExponent;

        /// <summary>
        /// Basic constructor for an RSA public key from its numeric components.
        /// </summary>
        /// <param name="algorithm">The algorithm marker.</param>
        /// <param name="modulus">The modulus.</param>
        /// <param name="publicExponent">The public exponent.</param>
		public AsymmetricRsaPublicKey(Algorithm algorithm, BigInteger modulus, BigInteger publicExponent)
            : base(algorithm, KeyUtils.Validated(modulus, publicExponent))
		{
			this.publicExponent = publicExponent;
		}

        /// <summary>
        /// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing an RSA public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfoEncoding">An encoding of a SubjectPublicKeyInfo object.</param>
        public AsymmetricRsaPublicKey(Algorithm algorithm, byte[] publicKeyInfoEncoding)
            : this(algorithm, SubjectPublicKeyInfo.GetInstance(publicKeyInfoEncoding))
		{
		}

        /// <summary>
        /// Constructor from an algorithm and a SubjectPublicKeyInfo object containing an RSA public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricRsaPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
            : this(algorithm, publicKeyInfo.AlgorithmID, ParsePublicKey(publicKeyInfo))
		{
		}

		private static RsaPublicKeyStructure ParsePublicKey(SubjectPublicKeyInfo publicKeyInfo)
		{
			try
			{
				return RsaPublicKeyStructure.GetInstance(publicKeyInfo.GetPublicKey());
			}
			catch (Exception e)
			{
				throw new ArgumentException("Unable to parse public key: " + e.Message, e);
			}
		}

		private AsymmetricRsaPublicKey(Algorithm algorithm, AlgorithmIdentifier pubKeyAlgorithm, RsaPublicKeyStructure pubKey)
            : base(algorithm, pubKeyAlgorithm, KeyUtils.Validated(pubKey.Modulus, pubKey.PublicExponent))
		{
			this.publicExponent = pubKey.PublicExponent;
		}

        /// <summary>
        /// Return the public exponent.
        /// </summary>
        public virtual BigInteger PublicExponent
        {
			get { return publicExponent; }
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
		{
			return KeyUtils.GetEncodedSubjectPublicKeyInfo(rsaAlgIdentifier, new RsaPublicKeyStructure(Modulus, PublicExponent));
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}
			if (!(o is AsymmetricRsaPublicKey))
			{
				return false;
			}

			AsymmetricRsaPublicKey other = (AsymmetricRsaPublicKey)o;

            return Modulus.Equals(other.Modulus)
                && PublicExponent.Equals(other.PublicExponent);
		}

		public override int GetHashCode()
		{
			int result = Modulus.GetHashCode();
			result = 31 * result + publicExponent.GetHashCode();
			return result;
		}

        Func<IKey, IPublicKeyRsaService> IServiceProvider<IPublicKeyRsaService>.GetFunc(SecurityContext context)
        {
            return (key) => new PublicKeyRsaService(key);
        }

        private class PublicKeyRsaService : IPublicKeyRsaService
        {
            private readonly IKey publicKey;

            public PublicKeyRsaService(IKey publicKey)
            {
                this.publicKey = publicKey;
            }

            public IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                Rsa.Pkcs1v15WrapParameters pkcsP = algorithmDetails as Rsa.Pkcs1v15WrapParameters;
                if (pkcsP != null)
                {
                    CryptoServicesRegistrar.ApprovedModeCheck(false, "RSA");
                    General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                    return (IKeyWrapper<A>)new Rsa.Pkcs1v15KeyWrapper(pkcsP, publicKey);
                }

                return (IKeyWrapper<A>)new Fips.FipsRsa.RsaKeyWrapper(algorithmDetails as Fips.FipsRsa.OaepWrapParameters, publicKey);
            }

            public IVerifierFactory<A> CreateVerifierFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                Fips.FipsRsa.PssSignatureParameters pssParams = algorithmDetails as Fips.FipsRsa.PssSignatureParameters;
                if (pssParams != null)
                {
                    return (IVerifierFactory<A>)new VerifierFactory<Fips.FipsRsa.PssSignatureParameters>(pssParams, new Fips.FipsRsa.PssSignerProvider(pssParams, publicKey));
                }

                Fips.FipsRsa.SignatureParameters sigParams = algorithmDetails as Fips.FipsRsa.SignatureParameters;

                return (IVerifierFactory<A>)new VerifierFactory<Fips.FipsRsa.SignatureParameters>(sigParams, new Fips.FipsRsa.SignerProvider(sigParams, publicKey));
            }
        }
    }
}
