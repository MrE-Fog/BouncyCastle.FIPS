
using System;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Class for NewHope (NH) public keys.
    /// </summary>
    public class AsymmetricNHPublicKey: AsymmetricNHKey, IAsymmetricPublicKey
    {
        private readonly byte[] mKeyData;
        
        internal AsymmetricNHPublicKey(byte[] keyData): base(General.NewHope.Alg)
        {
            this.mKeyData = Arrays.Clone(keyData);
        }

        /// <summary>
        /// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing a NewHope public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="enc">An encoding of a SubjectPublicKeyInfo object.</param>
        public AsymmetricNHPublicKey(Algorithm algorithm, byte[] enc)
            : this(algorithm, SubjectPublicKeyInfo.GetInstance(enc))
		{
        }

        /// <summary>
        /// Constructor from an algorithm and a SubjectPublicKeyInfo object containing a NewHope public key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricNHPublicKey(Algorithm algorithm, SubjectPublicKeyInfo publicKeyInfo)
            : base(algorithm)
		{
            this.mKeyData = Arrays.Clone(publicKeyInfo.PublicKeyData.GetOctets());
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
        {
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.newHope), mKeyData);

            return KeyUtils.GetEncodedInfo(info);
        }

        public byte[] GetKeyData()
        {
            return Arrays.Clone(mKeyData);
        }

        public override bool Equals(object o)
        {
            if (this == o)
            {
                return true;
            }

            if (!(o is AsymmetricNHPublicKey))
            {
                return false;
            }

            AsymmetricNHPublicKey other = (AsymmetricNHPublicKey)o;

            return Arrays.AreEqual(mKeyData, other.mKeyData);
        }

        public override int GetHashCode()
        {
            return Arrays.GetHashCode(mKeyData);
        }
    }
}
