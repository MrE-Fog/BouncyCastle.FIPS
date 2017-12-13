using System;

using Org.BouncyCastle.Math;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeyDsaService : ISignatureFactoryService
    {

    }

    /// <summary>
    /// Class for Digital Signature Algorithm (DSA) private keys.
    /// </summary>
    public class AsymmetricDsaPrivateKey
        : AsymmetricDsaKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeyDsaService>, IServiceProvider<IPrivateKeyDsaService>
    {
		private readonly int hashCode;

		private BigInteger x;

        /// <summary>
        /// Base constructor for a DSA private key.
        /// </summary>
        /// <param name="algorithm">The algorithm marker for this key.</param>
        /// <param name="parameters">The domain parameters for this key.</param>
        /// <param name="x">The private X value for this key.</param>
		public AsymmetricDsaPrivateKey(Algorithm algorithm, DsaDomainParameters parameters, BigInteger x)
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
		public AsymmetricDsaPrivateKey(Algorithm algorithm, byte[] enc)
            : this(algorithm, PrivateKeyInfo.GetInstance(enc))
		{
		}

        /// <summary>
        /// Constructor from an algorithm and a PrivateKeyInfo object containing a DSA private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="privateKeyInfo">A PrivateKeyInfo object.</param>
        public AsymmetricDsaPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
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
			DsaDomainParameters dsaDomainParameters = this.DomainParameters;

			return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa, new DsaParameter(dsaDomainParameters.P, dsaDomainParameters.Q, dsaDomainParameters.G)), new DerInteger(X));
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

			return x.Equals(other.x) && this.DomainParameters.Equals(other.DomainParameters);
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

        Func<IKey, IPrivateKeyDsaService> IServiceProvider<IPrivateKeyDsaService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeyDsaService(key);
        }

        private class PrivateKeyDsaService : IPrivateKeyDsaService
        {
            private readonly bool approvedOnlyMode;
            private readonly IKey privateKey;

            public PrivateKeyDsaService(IKey privateKey)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.privateKey = privateKey;
            }

            public ISignatureFactory<A> CreateSignatureFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DSA");

                if (algorithmDetails is Fips.FipsDsa.SignatureParameters)
                {
                    return (ISignatureFactory<A>)new SignatureFactory<Fips.FipsDsa.SignatureParameters>(algorithmDetails as Fips.FipsDsa.SignatureParameters, new Fips.FipsDsa.SignerProvider(algorithmDetails as Fips.FipsDsa.SignatureParameters, privateKey));
                }
                else
                {
                    General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                    return (ISignatureFactory<A>)new SignatureFactory<General.Dsa.SignatureParameters>(algorithmDetails as General.Dsa.SignatureParameters, new General.Dsa.SignerProvider(algorithmDetails as General.Dsa.SignatureParameters, privateKey));
                }
            }
        }
    }
}

