using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPublicKeyDHService : IKeyWrappingService
    {

    }

    /// <summary>
    /// Class for Diffie-Hellman public keys.
    /// </summary>
    public class AsymmetricDHPublicKey
        : AsymmetricDHKey, IAsymmetricPublicKey, ICryptoServiceType<IPublicKeyDHService>, IServiceProvider<IPublicKeyDHService>
    {
        private BigInteger mY;
        private SubjectPublicKeyInfo publicKeyInfo;

        public AsymmetricDHPublicKey(Algorithm algorithm, DHDomainParameters parameters, BigInteger y)
            : base(algorithm, parameters)
        {
            this.mY = KeyUtils.Validated(parameters, y);
        }

        /// <summary>
        /// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing a Diffie-Hellman public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="enc">An encoding of a SubjectPublicKeyInfo object.</param>
        public AsymmetricDHPublicKey(Algorithm algorithm, byte[] enc)
            : this(algorithm, SubjectPublicKeyInfo.GetInstance(enc))
        {
        }

        /// <summary>
        /// Constructor from an algorithm and a SubjectPublicKeyInfo object containing a Diffie-Hellman public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricDHPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
            : base(algorithm, publicKeyInfo.AlgorithmID)
        {
            this.mY = KeyUtils.Validated(DomainParameters, ParsePublicKey(publicKeyInfo));
            this.publicKeyInfo = publicKeyInfo;
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
            get { return mY; }
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
        {
            DHDomainParameters dhParams = this.DomainParameters;

            if (publicKeyInfo != null)
            {
                return KeyUtils.GetEncodedInfo(publicKeyInfo);
            }

            if (dhParams.Q == null)
            {
                if (Algorithm.Name.StartsWith("ELGAMAL"))
                {
                    return KeyUtils.GetEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(OiwObjectIdentifiers.ElGamalAlgorithm, new ElGamalParameter(dhParams.P, dhParams.G)), new DerInteger(mY));
                }
                return KeyUtils.GetEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PkcsObjectIdentifiers.DhKeyAgreement, new DHParameter(dhParams.P, dhParams.G, dhParams.L)), new DerInteger(mY));
            }
            else
            {
                DHValidationParameters validationParameters = dhParams.ValidationParameters;

                if (validationParameters != null)
                {
                    return KeyUtils.GetEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, new Asn1.X9.DHDomainParameters(dhParams.P, dhParams.G, dhParams.Q, dhParams.J,
                        new DHValidationParms(validationParameters.GetSeed(), BigInteger.ValueOf(validationParameters.Counter)))), new DerInteger(mY));
                }
                else
                {
                    return KeyUtils.GetEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.DHPublicNumber, new Asn1.X9.DHDomainParameters(dhParams.P, dhParams.G, dhParams.Q, dhParams.J, null)), new DerInteger(mY));
                }
            }
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

            return mY.Equals(other.Y) && this.DomainParameters.Equals(other.DomainParameters);
        }

        public override int GetHashCode()
        {
            int result = mY.GetHashCode();
            result = 31 * result + this.DomainParameters.GetHashCode();
            return result;
        }

        Func<IKey, IPublicKeyDHService> IServiceProvider<IPublicKeyDHService>.GetFunc(SecurityContext context)
        {
            return (key) => new PublicKeyDHService(key);
        }

        private class PublicKeyDHService : IPublicKeyDHService
        {
            private readonly bool approvedOnlyMode;
            private readonly IKey publicKey;

            public PublicKeyDHService(IKey publicKey)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.publicKey = publicKey;
            }

            public IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "DH");
                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                ElGamal.OaepWrapParameters oaepP = algorithmDetails as ElGamal.OaepWrapParameters;
                if (oaepP != null)
                {
                    return (IKeyWrapper<A>)new ElGamal.OaepKeyWrapper(oaepP, publicKey);
                }

                ElGamal.Pkcs1v15WrapParameters pkcsP = algorithmDetails as ElGamal.Pkcs1v15WrapParameters;
                if (pkcsP != null)
                {
                    return (IKeyWrapper<A>)new ElGamal.Pkcs1v15KeyWrapper(pkcsP, publicKey);
                }

                throw new ArgumentException("unknown algorithm parameters");
            }
        }
    }
}

