using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

using NewHopeImpl = Org.BouncyCastle.Crypto.Internal.Agreement.NewHope;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeyNHService : IAgreementCalculatorService
    {
    }

    /// <summary>
    /// Class for NewHope (NH) private keys.
    /// </summary>
    public class AsymmetricNHPrivateKey
        : AsymmetricNHKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeyNHService>, IServiceProvider<IPrivateKeyNHService>
    {
        private readonly ushort[] privateKeyData;

        /// <summary>
        /// Constructor from an algorithm and an encoding of a PrivateKeyInfo object containing a NewHope private key.
        /// </summary>
        /// <param name="alg">Algorithm marker to associate with the key.</param>
        /// <param name="encoding">An encoding of a PrivateKeyInfo object.</param>
        public AsymmetricNHPrivateKey(Algorithm alg, byte[] encoding) : this(alg, PrivateKeyInfo.GetInstance(encoding))
        {
        }

        /// <summary>
        /// Constructor from an algorithm and a PrivateKeyInfo object containing a NewHope private key.
        /// </summary>
        /// <param name="algorithm">Algorithm marker to associate with the key.</param>
        /// <param name="privateKeyInfo">A PrivateKeyInfo object.</param>
        public AsymmetricNHPrivateKey(Algorithm algorithm, PrivateKeyInfo privateKeyInfo): base(algorithm) 
		{
            this.privateKeyData = Convert(Asn1OctetString.GetInstance(privateKeyInfo.ParsePrivateKey()).GetOctets());
        }

        internal AsymmetricNHPrivateKey(ushort[] privateKeyData)
            : base(General.NewHope.Alg)
        {
            this.privateKeyData = privateKeyData;
        }

        private static ushort[] Convert(byte[] octets)
        {
            ushort[] rv = new ushort[octets.Length / 2];

            for (int i = 0; i != rv.Length; i++)
            {
                rv[i] = Pack.LE_To_UInt16(octets, i * 2);
            }

            return rv;
        }

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key in a PrivateKeyInfo structure.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public override byte[] GetEncoded()
        {
            CheckApprovedOnlyModeStatus();

            //KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

            byte[] octets = new byte[privateKeyData.Length * 2];
            for (int i = 0; i != privateKeyData.Length; i++)
            {
                Pack.UInt16_To_LE(privateKeyData[i], octets, i * 2);
            }

            return KeyUtils.GetEncodedPrivateKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.newHope), new DerOctetString(octets));
        }

        public override bool Equals(object o)
        {
            CheckApprovedOnlyModeStatus();

            if (this == o)
            {
                return true;
            }

            if (!(o is AsymmetricNHPrivateKey))
            {
                return false;
            }

            AsymmetricNHPrivateKey other = (AsymmetricNHPrivateKey)o;

            if (privateKeyData.Length != other.privateKeyData.Length)
            {
                return false;
            }

            for (int i = 0; i != privateKeyData.Length; i++)
            {
                if (privateKeyData[i] != other.privateKeyData[i])
                {
                    return false;
                }
            }

            return true;
        }

        public override int GetHashCode()
        {
            CheckApprovedOnlyModeStatus();

            return Arrays.GetHashCode(privateKeyData);
        }

        Func<IKey, IPrivateKeyNHService> IServiceProvider<IPrivateKeyNHService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeyNHService(key);
        }

        private class PrivateKeyNHService : IPrivateKeyNHService
        {
            private readonly AsymmetricNHPrivateKey privateKey;

            public PrivateKeyNHService(IKey key)
            {
                if (key is KeyWithRandom)
                {
                    throw new ArgumentException("SecureRandom not required for final step in NewHope agreement");
                }
                else
                {
                    this.privateKey = (AsymmetricNHPrivateKey)key;
                }
            }

            public IAgreementCalculator<A> CreateAgreementCalculator<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                return new AgreementCalc<A>(algorithmDetails, privateKey);
            }

            private class AgreementCalc<A> : IAgreementCalculator<A> where A : IParameters<Algorithm>
            {
                private readonly A algDetails;
                private readonly AsymmetricNHPrivateKey privateKey;

                internal AgreementCalc(A algorithmDetails, AsymmetricNHPrivateKey privateKey)
                {
                    this.algDetails = algorithmDetails;
                    this.privateKey = privateKey;
                }

                public A AlgorithmDetails
                {
                    get { return algDetails; }
                }

                public byte[] Calculate(IAsymmetricPublicKey publicKey)
                {
                    General.Utils.ApprovedModeCheck("service", algDetails.Algorithm);

                    byte[] receivedKey = ((AsymmetricNHPublicKey)publicKey).GetKeyData();
                    byte[] sharedKey = new byte[NewHopeImpl.AgreementSize];

                    NewHopeImpl.SharedA(sharedKey, privateKey.privateKeyData, receivedKey);

                    return sharedKey;
                }
            }
        }
    }
}
