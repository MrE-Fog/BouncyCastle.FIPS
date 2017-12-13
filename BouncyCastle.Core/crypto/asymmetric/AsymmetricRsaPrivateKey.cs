using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeyRsaService : IKeyUnwrappingService, ISignatureFactoryService
    {

    }

    /// <summary>
    /// Class for RSA private keys.
    /// </summary>
    public class AsymmetricRsaPrivateKey
        : AsymmetricRsaKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeyRsaService>, IServiceProvider<IPrivateKeyRsaService>
    {
		private BigInteger publicExponent;
		private BigInteger privateExponent;
		private BigInteger p;
		private BigInteger q;
		private BigInteger dp;
		private BigInteger dq;
		private BigInteger qInv;

		private readonly int hashCode;

        /// <summary>
        /// Basic constructor for an RSA private key with CRT factors.
        /// </summary>
        /// <param name="algorithm">Algorithm marker.</param>
        /// <param name="modulus">The modulus.</param>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="privateExponent">The private exponent.</param>
        /// <param name="p">The prime P.</param>
        /// <param name="q">The prime Q.</param>
        /// <param name="dp">The prime exponent of P.</param>
        /// <param name="dq">The prime exponent of Q.</param>
        /// <param name="qInv">The CRT coefficient.</param>
		public AsymmetricRsaPrivateKey(Algorithm algorithm, 
			BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, 
			BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qInv)
            : base(algorithm, KeyUtils.ValidatedModulus(modulus))
		{
			this.publicExponent = publicExponent;
			this.privateExponent = privateExponent;
			this.p = p;
			this.q = q;
			this.dp = dp;
			this.dq = dq;
			this.qInv = qInv;
			this.hashCode = CalculateHashCode();
		}

        /// <summary>
        /// Basic constructor for an RSA private key with simple components.
        /// </summary>
        /// <param name="algorithm">Algorithm marker.</param>
        /// <param name="modulus">The modulus.</param>
        /// <param name="privateExponent">The private exponent.</param>
        public AsymmetricRsaPrivateKey(Algorithm algorithm, BigInteger modulus, BigInteger privateExponent)
            : base(algorithm, KeyUtils.ValidatedModulus(modulus))
		{
			this.privateExponent = privateExponent;
			this.publicExponent = BigInteger.Zero;
			this.p = BigInteger.Zero;
			this.q = BigInteger.Zero;
			this.dp = BigInteger.Zero;
			this.dq = BigInteger.Zero;
			this.qInv = BigInteger.Zero;
			this.hashCode = CalculateHashCode();
		}

        /// <summary>
        /// Constructor from an algorithm and an encoding of a PrivateKeyInfo object containing an RSA private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="encoding">An encoding of a PrivateKeyInfo object.</param>
        public AsymmetricRsaPrivateKey(Algorithm algorithm, byte[] encoding)
            : this(algorithm, GetPrivateKeyInfo(encoding))
		{
		}

        /// <summary>
        /// Constructor from an algorithm and a PrivateKeyInfo object containing an RSA private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="privateKeyInfo">A PrivateKeyInfo object.</param>
        public AsymmetricRsaPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
            : this(algorithm, privateKeyInfo.PrivateKeyAlgorithm, ParsePrivateKey(privateKeyInfo))
		{
		}

		private static PrivateKeyInfo GetPrivateKeyInfo(byte[] encoding)
		{
			try
			{
				return PrivateKeyInfo.GetInstance(encoding);
			}
			catch (ArgumentException e)
			{
				// OpenSSL's old format, and some others - Try just the private key data.
				try
				{
					return new PrivateKeyInfo(DEF_ALG_ID, Asn1Sequence.GetInstance(encoding));
				}
				catch (Exception)
				{
					throw new ArgumentException("Unable to parse private key: " + e.Message, e);
				}
			}
		}

		private static RsaPrivateKeyStructure ParsePrivateKey(PrivateKeyInfo privateKeyInfo)
		{
			try
			{
				return RsaPrivateKeyStructure.GetInstance(privateKeyInfo.ParsePrivateKey());
			}
			catch (Exception e)
			{
				throw new ArgumentException("Unable to parse private key: " + e.Message, e);
			}
		}

		private AsymmetricRsaPrivateKey(Algorithm algorithm, AlgorithmIdentifier algId, RsaPrivateKeyStructure privKey)
            : base(algorithm, algId, KeyUtils.ValidatedModulus(privKey.Modulus))
		{
			this.publicExponent = privKey.PublicExponent;
			this.privateExponent = privKey.PrivateExponent;
			this.p = privKey.Prime1;
			this.q = privKey.Prime2;
			this.dp = privKey.Exponent1;
			this.dq = privKey.Exponent2;
			this.qInv = privKey.Coefficient;
			this.hashCode = CalculateHashCode();
		}

        /// <summary>
        /// Return the public exponent.
        /// </summary>
		public virtual BigInteger PublicExponent
		{
			get { return publicExponent; }
		}

        /// <summary>
        /// Return the private exponent.
        /// </summary>
		public virtual BigInteger PrivateExponent
		{
			get
            {
			    CheckCanRead();
			    return privateExponent;
		    }
		}

        /// <summary>
        /// Return the prime P.
        /// </summary>
		public virtual BigInteger P
        {
			get
            {
				CheckCanRead();
				return p;
			}
		}

        /// <summary>
        /// Return the prime Q.
        /// </summary>
		public virtual BigInteger Q
        {
			get
            {
				CheckCanRead();
				return q;
			}
		}

        /// <summary>
        /// Return the prime exponent of P.
        /// </summary>
		public virtual BigInteger DP
        {
			get
            {
				CheckCanRead();
				return dp;
			}
		}

        /// <summary>
        /// Return the prime exponent of Q.
        /// </summary>
		public virtual BigInteger DQ
        {
			get
            {
				CheckCanRead();
				return dq;
			}
		}

        /// <summary>
        /// Return the CRT coefficient.
        /// </summary>
		public virtual BigInteger QInv
        {
			get
			{
                CheckCanRead();
				return qInv;
			}
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a PrivateKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
		{
			CheckApprovedOnlyModeStatus();

			//KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

			return KeyUtils.GetEncodedPrivateKeyInfo(rsaAlgIdentifier,
                new RsaPrivateKeyStructure(Modulus, publicExponent, PrivateExponent, P, Q, DP, DQ, QInv));
		}

		public override bool Equals(object o)
		{
			CheckApprovedOnlyModeStatus();

			if (this == o)
			{
				return true;
			}
			if (!(o is AsymmetricRsaPrivateKey))
			{
				return false;
			}

			AsymmetricRsaPrivateKey other = (AsymmetricRsaPrivateKey)o;

			return Modulus.Equals(other.Modulus)
				&& privateExponent.Equals(other.privateExponent) && PublicExponent.Equals(other.PublicExponent)
				&& p.Equals(other.p) && q.Equals(other.q)
				&& dp.Equals(other.dp) && dq.Equals(other.dq) && qInv.Equals(other.qInv);
		}

		public override int GetHashCode()
		{
			CheckApprovedOnlyModeStatus();
			return hashCode;
		}

        private int CalculateHashCode()
        {
            int result = Modulus.GetHashCode();
            result = 31 * result + publicExponent.GetHashCode();
            result = 31 * result + privateExponent.GetHashCode();
            result = 31 * result + p.GetHashCode();
            result = 31 * result + q.GetHashCode();
            result = 31 * result + dp.GetHashCode();
            result = 31 * result + dq.GetHashCode();
            result = 31 * result + qInv.GetHashCode();
            return result;
        }

        private void CheckCanRead()
		{
			CheckApprovedOnlyModeStatus();

			//KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);
		}

        Func<IKey, IPrivateKeyRsaService> IServiceProvider<IPrivateKeyRsaService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeyRsaService(key);
        }

        private class PrivateKeyRsaService : IPrivateKeyRsaService
        {
            private readonly bool approvedOnlyMode;
            private readonly IKey privateKey;

            public PrivateKeyRsaService(IKey privateKey)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.privateKey = privateKey;
            }

            public IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "RSA");

                Rsa.Pkcs1v15WrapParameters pkcsP = algorithmDetails as Rsa.Pkcs1v15WrapParameters;
                if (pkcsP != null)
                {
                    CryptoServicesRegistrar.ApprovedModeCheck(false, "RSA");
                    General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                    return (IKeyUnwrapper<A>)new Rsa.Pkcs1v15KeyUnwrapper(pkcsP, privateKey);
                }

                return (IKeyUnwrapper<A>)new Fips.FipsRsa.RsaKeyUnwrapper(algorithmDetails as Fips.FipsRsa.OaepWrapParameters, privateKey);
            }

            public ISignatureFactory<A> CreateSignatureFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "RSA");

                Fips.FipsRsa.PssSignatureParameters pssParams = algorithmDetails as Fips.FipsRsa.PssSignatureParameters;
                if (pssParams != null)
                {
                    return (ISignatureFactory<A>)new SignatureFactory<Fips.FipsRsa.PssSignatureParameters>(pssParams, new Fips.FipsRsa.PssSignerProvider(pssParams, privateKey));
                }

                Fips.FipsRsa.SignatureParameters sigParams = algorithmDetails as Fips.FipsRsa.SignatureParameters;

                return (ISignatureFactory<A>)new SignatureFactory<Fips.FipsRsa.SignatureParameters>(sigParams, new Fips.FipsRsa.SignerProvider(sigParams, privateKey));
            }
        }

    }
}
