using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeySphincsService : ISignatureFactoryService
    {

    }

    /// <summary>
    /// Representation for SPHINCS-256 private keys.
    /// </summary>
    public class AsymmetricSphincsPrivateKey: AsymmetricSphincsKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeySphincsService>, IServiceProvider<IPrivateKeySphincsService>
    {
        private readonly byte[] keyData;

        /// <summary>
        /// Constructor from an algorithm and an encoding of a PrivateKeyInfo object containing a SPHINCS private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="encoding">An encoding of a PrivateKeyInfo object.</param>
        public AsymmetricSphincsPrivateKey(Algorithm algorithm, byte[] encoding) : this(algorithm, PrivateKeyInfo.GetInstance(encoding))
        {
        }

        /// <summary>
        /// Constructor from an algorithm and a PrivateKeyInfo object containing a SPHINCS private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="privateKeyInfo">A PrivateKeyInfo object.</param>
        public AsymmetricSphincsPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo)
            : base(algorithm, privateKeyInfo.PrivateKeyAlgorithm) 
		{
            this.keyData = Arrays.Clone(Asn1OctetString.GetInstance(privateKeyInfo.ParsePrivateKey()).GetOctets());
        }

        internal AsymmetricSphincsPrivateKey(Algorithm alg, DigestAlgorithm treeAlgorithm, byte[] keyData): base(alg, treeAlgorithm)
        {
            this.keyData = Arrays.Clone(keyData);
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a PrivateKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
        {
            checkApprovedOnlyModeStatus();

            return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256, parameters), new DerOctetString(keyData));
        }

        /// <summary>
        /// Return the key data (a byte representation of the digest tree used in signature generation).
        /// </summary>
        /// <returns>The key data.</returns>
        public override byte[] GetKeyData()
        {
            checkApprovedOnlyModeStatus();

            return Arrays.Clone(keyData);
        }

        public override bool Equals(object o)
        {
            checkApprovedOnlyModeStatus();

            if (this == o)
            {
                return true;
            }

            if (!(o is AsymmetricSphincsPrivateKey))
            {
                return false;
            }

            AsymmetricSphincsPrivateKey other = (AsymmetricSphincsPrivateKey)o;

            return this.parameters.Equals(other.parameters) && Arrays.AreEqual(keyData, other.keyData);
        }

        public override int GetHashCode()
        {
            checkApprovedOnlyModeStatus();

            return parameters.GetHashCode() + 37 * Arrays.GetHashCode(keyData);
        }

        Func<IKey, IPrivateKeySphincsService> IServiceProvider<IPrivateKeySphincsService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeySphincsService(key);
        }

        private class PrivateKeySphincsService : IPrivateKeySphincsService
        {
            private readonly IKey privateKey;

            public PrivateKeySphincsService(IKey privateKey)
            {
                if (privateKey is KeyWithRandom)
                {
                    throw new ArgumentException("no SecureRandom required for SPHINCS-256");
                }

                this.privateKey = privateKey;
            }

            public ISignatureFactory<A> CreateSignatureFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);
                General.Sphincs.SignatureParameters sigParams = algorithmDetails as General.Sphincs.SignatureParameters;

                AsymmetricSphincsKey key = (AsymmetricSphincsKey)privateKey;

                return (ISignatureFactory<A>)new SignatureFactory<General.Sphincs.SignatureParameters>(new General.Sphincs.SignatureParameters(sigParams, key.TreeDigestAlgorithm), new General.Sphincs.SignerProvider(sigParams, key));
            }
        }
    }
}
