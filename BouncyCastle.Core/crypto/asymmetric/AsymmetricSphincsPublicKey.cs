using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPublicKeySphincsService : IVerifierFactoryService
    {

    }

    /// <summary>
    /// Representation for SPHINCS-256 public keys.
    /// </summary>
    public class AsymmetricSphincsPublicKey : AsymmetricSphincsKey, IAsymmetricPublicKey, ICryptoServiceType<IPublicKeySphincsService>, IServiceProvider<IPublicKeySphincsService>
    {
        private readonly byte[] keyData;

        internal AsymmetricSphincsPublicKey(Algorithm alg, DigestAlgorithm treeAlgorithm, byte[] keyData): base(alg, treeAlgorithm)
        {
            this.keyData = Arrays.Clone(keyData);
        }

        /// <summary>
        /// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing a SPHINCS public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="enc">An encoding of a SubjectPublicKeyInfo object.</param>
        public AsymmetricSphincsPublicKey(Algorithm algorithm, byte[] enc)
            : this(algorithm, SubjectPublicKeyInfo.GetInstance(enc))
		{
        }

        /// <summary>
        /// Constructor from an algorithm and a SubjectPublicKeyInfo object containing a SPHINCS public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricSphincsPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
            : base(algorithm, publicKeyInfo.AlgorithmID)
		{
            this.keyData = Arrays.Clone(publicKeyInfo.PublicKeyData.GetOctets());
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
        {
            SubjectPublicKeyInfo info;

            info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256, parameters), keyData);

            return KeyUtils.GetEncodedInfo(info);
        }

        /// <summary>
        /// Return the key data (a byte representation of the digest tree used in signature verification).
        /// </summary>
        /// <returns>The key data.</returns>
        public override byte[] GetKeyData()
        {
            return Arrays.Clone(keyData);
        }

        public override bool Equals(object o)
        {
            if (this == o)
            {
                return true;
            }

            if (!(o is AsymmetricSphincsPublicKey))
            {
                return false;
            }

            AsymmetricSphincsPublicKey other = (AsymmetricSphincsPublicKey)o;

            return this.parameters.Equals(other.parameters) && Arrays.AreEqual(keyData, other.keyData);
        }

        public override int GetHashCode()
        {
            return parameters.GetHashCode() + 37 * Arrays.GetHashCode(keyData);
        }

        Func<IKey, IPublicKeySphincsService> IServiceProvider<IPublicKeySphincsService>.GetFunc(SecurityContext context)
        {
            return (key) => new PublicKeySphincsService(key);
        }

        private class PublicKeySphincsService : IPublicKeySphincsService
        {
            private readonly AsymmetricSphincsPublicKey publicKey;

            public PublicKeySphincsService(IKey publicKey)
            {
                this.publicKey = (AsymmetricSphincsPublicKey)publicKey;
            }

            public IVerifierFactory<A> CreateVerifierFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);
                General.Sphincs.SignatureParameters algDets = algorithmDetails as General.Sphincs.SignatureParameters;

                if (algDets.DigestAlgorithm == FipsShs.Sha512 && publicKey.TreeDigestAlgorithm != FipsShs.Sha512_256)
                {
                    throw new ArgumentException("public key not generated with compatible tree hash");
                }
                if (algDets.DigestAlgorithm == FipsShs.Sha3_512 && publicKey.TreeDigestAlgorithm != FipsShs.Sha3_256)
                {
                    throw new ArgumentException("public key not generated with compatible tree hash");
                }
                return (IVerifierFactory<A>)new VerifierFactory<General.Sphincs.SignatureParameters>(algDets, new General.Sphincs.SignerProvider(algDets, publicKey));
            }
        }
    }
}
