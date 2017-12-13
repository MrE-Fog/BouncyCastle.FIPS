using System;

using Org.BouncyCastle.Math;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeyDHService : IKeyUnwrappingService
    {

    }

    /// <summary>
    /// Class for Digital Signature Algorithm (DSA) private keys.
    /// </summary>
    public class AsymmetricDHPrivateKey
        : AsymmetricDHKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeyDHService>, IServiceProvider<IPrivateKeyDHService>
    {
		private readonly int hashCode;

		private BigInteger x;

        /// <summary>
        /// Base constructor for a Diffie-Hellman private key.
        /// </summary>
        /// <param name="algorithm">The algorithm marker for this key.</param>
        /// <param name="parameters">The domain parameters for this key.</param>
        /// <param name="x">The private X value for this key.</param>
		public AsymmetricDHPrivateKey(Algorithm algorithm, DHDomainParameters parameters, BigInteger x)
            : base(algorithm, parameters)
		{
			this.x = x;
			this.hashCode = CalculateHashCode();
		}

        /// <summary>
        /// Constructor from an algorithm and an encoding of a PrivateKeyInfo object containing a DSA private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="enc">An encoding of a PrivateKeyInfo object.</param>
		public AsymmetricDHPrivateKey(Algorithm algorithm, byte[] enc)
            : this(algorithm, PrivateKeyInfo.GetInstance(enc))
		{
		}

        /// <summary>
        /// Constructor from an algorithm and a PrivateKeyInfo object containing a DSA private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="privateKeyInfo">A PrivateKeyInfo object.</param>
        public AsymmetricDHPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
            : base(algorithm, privateKeyInfo.PrivateKeyAlgorithm) 
		{
			this.x = ParsePrivateKey(privateKeyInfo);
			this.hashCode = CalculateHashCode();
		}

		private static BigInteger ParsePrivateKey(PrivateKeyInfo info)
		{
			try
			{
				return DerInteger.GetInstance(info.ParsePrivateKey()).Value;
			}
			catch (Exception e)
			{
				throw new ArgumentException("Unable to parse DSA private key: " + e.Message, e);
			}
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a PrivateKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
		{
            DHDomainParameters dhParams = this.DomainParameters;

            if (dhParams.Q == null)
            {
                if (Algorithm.Name.StartsWith("ELGAMAL"))
                {
                    return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(OiwObjectIdentifiers.ElGamalAlgorithm, new ElGamalParameter(dhParams.P, dhParams.G)), new DerInteger(X));
                }

                return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(PkcsObjectIdentifiers.DhKeyAgreement, new DHParameter(dhParams.P, dhParams.G, dhParams.L)), new DerInteger(X));
            }
            else
            {
                DHValidationParameters validationParameters = dhParams.ValidationParameters;
                if (validationParameters != null)
                {
                    return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, new Asn1.X9.DHDomainParameters(dhParams.P, dhParams.G, dhParams.Q, dhParams.J,
                        new DHValidationParms(new DerBitString(validationParameters.GetSeed()), new DerInteger(validationParameters.Counter)))), new DerInteger(X));
                }
                else
                {
                    return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, new Asn1.X9.DHDomainParameters(dhParams.P, dhParams.G, dhParams.Q, dhParams.J, null)), new DerInteger(X));
                }
            }
        }

        /// <summary>
        /// Return the private X value.
        /// </summary>
		public virtual BigInteger X
        {
            get
            {
                CheckApprovedOnlyModeStatus();
                //KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);
                return x;
            }
        }

        private void Zeroize()
		{
			this.x = null;
		}

        /// <summary>
        /// Compare this key to another object.
        /// </summary>
        /// <param name="o">The other object.</param>
        /// <returns>true if this equals o, false otherwise.</returns>
		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			if (!(o is AsymmetricDsaPrivateKey))
			{
				return false;
			}

			AsymmetricDsaPrivateKey other = (AsymmetricDsaPrivateKey)o;

			return x.Equals(other.X) && this.DomainParameters.Equals(other.DomainParameters);
		}

        /// <summary>
        /// Return the hashcode for this key.
        /// </summary>
        /// <returns>The key's hashcode.</returns>
		public override int GetHashCode()
		{
			return hashCode;
		}

		private int CalculateHashCode()
		{
			int result = x.GetHashCode();
			result = 31 * result + this.DomainParameters.GetHashCode();
			return result;
		}

        Func<IKey, IPrivateKeyDHService> IServiceProvider<IPrivateKeyDHService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeyDHService(key);
        }

        private class PrivateKeyDHService : IPrivateKeyDHService
        {
            private readonly bool approvedOnlyMode;
            private readonly IKey privateKey;

            public PrivateKeyDHService(IKey privateKey)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.privateKey = privateKey;
            }

            public IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DH");
                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                ElGamal.OaepWrapParameters oaepP = algorithmDetails as ElGamal.OaepWrapParameters;
                if (oaepP != null)
                {
                    return (IKeyUnwrapper<A>)new ElGamal.OaepKeyUnwrapper(oaepP, privateKey);
                }

                ElGamal.Pkcs1v15WrapParameters pkcsP = algorithmDetails as ElGamal.Pkcs1v15WrapParameters;
                if (pkcsP != null)
                {
                    return (IKeyUnwrapper<A>)new ElGamal.Pkcs1v15KeyUnwrapper(pkcsP, privateKey);
                }

                throw new ArgumentException("unknown algorithm parameters");
            }
        }
    }
}

