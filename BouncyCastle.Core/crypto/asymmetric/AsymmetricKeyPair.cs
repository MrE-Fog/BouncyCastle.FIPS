using Org.BouncyCastle.Crypto.Internal.Pqc.Crypto.Sphincs;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	/// <summary>
	/// Carrier class for a public key and its associated private key. This class will check the key
	/// pair on construction.
	/// </summary>
	public class AsymmetricKeyPair<TPub, TPriv> where TPub: IAsymmetricPublicKey where TPriv: IAsymmetricPrivateKey
	{
		private readonly TPub publicKey;
		private readonly TPriv privateKey;

		/**
     * Create a public/private key pair.
     *
     * @param publicKey the public key component.
     * @param privateKey the private key component.
     * @throws IllegalArgumentException if the public and private key arguments are inconsistent.
     */
		public AsymmetricKeyPair(TPub publicKey, TPriv privateKey)
		{
            // FSM_STATE:5.9,"IMPORTED KEY PAIR CONSISTENCY TEST", "The module is verifying the consistency of an imported key pair"
            // FSM_TRANS:5.IKP.0,"CONDITIONAL TEST", "IMPORTED KEY PAIR CONSISTENCY TEST", "Invoke public/private key Consistency test on imported key pair"
            checkKeyPairForConsistency(publicKey, privateKey);
            // FSM_TRANS:5.IKP.1, "IMPORTED KEY PAIR CONSISTENCY TEST", "CONDITIONAL TEST", "Consistency test on imported key pair successful"

            this.publicKey=publicKey;
			this.privateKey=privateKey;
		}
	
		private void checkKeyPairForConsistency(TPub publicKey, TPriv privateKey)
		{
            if (publicKey is AsymmetricECKey && privateKey is AsymmetricECKey)
            {
                AsymmetricECPrivateKey priv = privateKey as AsymmetricECPrivateKey;
                AsymmetricECPublicKey pub = publicKey as AsymmetricECPublicKey;

                if (!priv.DomainParameters.Equals(pub.DomainParameters))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("EC keys do not have the same domain parameters");
                }
                if (!priv.DomainParameters.G.Multiply(priv.S).Normalize().Equals(pub.W))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("EC public key not consistent with EC private key");
                }
            }
            else if (publicKey is AsymmetricDsaKey && privateKey is AsymmetricDsaKey)
            {
                AsymmetricDsaPrivateKey priv = privateKey as AsymmetricDsaPrivateKey;
                AsymmetricDsaPublicKey pub = publicKey as AsymmetricDsaPublicKey;

                DsaDomainParameters dsaParameters = priv.DomainParameters;
                if (!dsaParameters.Equals(pub.DomainParameters))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("DSA keys do not have the same domain parameters");
                }
                if (!dsaParameters.G.ModPow(priv.X, dsaParameters.P).Equals(pub.Y))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("DSA public key not consistent with DSA private key");
                }
            }
            else if (publicKey is AsymmetricRsaKey && privateKey is AsymmetricRsaKey)
            {
                AsymmetricRsaPrivateKey priv = privateKey as AsymmetricRsaPrivateKey;
                AsymmetricRsaPublicKey pub = publicKey as AsymmetricRsaPublicKey;

                if (!priv.Modulus.Equals(pub.Modulus))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("RSA keys do not have the same modulus");
                }
                BigInteger val = BigInteger.Two;
                if (!val.ModPow(priv.PrivateExponent, priv.Modulus).ModPow(pub.PublicExponent, priv.Modulus).Equals(val))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("RSA public key not consistent with RSA private key");
                }
            }
            else if (publicKey is AsymmetricDHKey && privateKey is AsymmetricDHKey)
            {
                AsymmetricDHPrivateKey priv = privateKey as AsymmetricDHPrivateKey;
                AsymmetricDHPublicKey pub = publicKey as  AsymmetricDHPublicKey;

                DHDomainParameters dhParameters = priv.DomainParameters;
                if (!dhParameters.Equals(pub.DomainParameters))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("DH keys do not have the same domain parameters");
                }
                if (!dhParameters.G.ModPow(priv.X, dhParameters.P).Equals(pub.Y))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("DH public key not consistent with DH private key");
                }
            }
            else if (publicKey is AsymmetricSphincsKey && privateKey is AsymmetricSphincsKey)
            {
                AsymmetricSphincsPrivateKey priv = privateKey as AsymmetricSphincsPrivateKey;
                AsymmetricSphincsPublicKey pub = publicKey as AsymmetricSphincsPublicKey;

                if (priv.TreeDigestAlgorithm != pub.TreeDigestAlgorithm)
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("Sphincs256 public key not consistent with Sphincs256 private key");
                }
                if (!IsRangeSame(priv.GetKeyData(), SPHINCS256Config.SEED_BYTES, pub.GetKeyData(), 0, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES))
                {
                    // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                    throw new ArgumentException("Sphincs256 public key not consistent with Sphincs256 private key");
                }
            }
            else if (publicKey is AsymmetricNHKey && privateKey is AsymmetricNHKey)
            {
                AsymmetricNHPrivateKey priv = privateKey as AsymmetricNHPrivateKey;
                AsymmetricNHPublicKey pub = publicKey as AsymmetricNHPublicKey;
                // currently there doesn't either a good approach or much point to this one as the keys should be ephemeral and always generated locally.
            }
            else
            {
                // FSM_TRANS:5.IKP.2, "IMPORTED KEY PAIR CONSISTENCY TEST", "USER COMMAND REJECTED", "Consistency test on imported key pair failed"
                throw new ArgumentException("Key pair inconsistent");
            }
		}

        private static bool IsRangeSame(byte[] a, int aOff, byte[] b, int bOff, int length)
        {
            if (aOff + length > a.Length || bOff + length > b.Length)
            {
                return false;
            }

            for (int i = 0; i != length; i++)
            {
                if (a[aOff + i] != b[bOff + i])
                {
                    return false;
                }
            }

            return true;
        }

		/// <summary>
		/// Gets the public key of the pair.
		/// </summary>
		/// <value>The public key.</value>
		public TPub PublicKey
		{
			get {
				return publicKey;
			}
		}
			
		/// <summary>
		/// Gets the private key of the pair.
		/// </summary>
		/// <value>The private key.</value>
		public TPriv PrivateKey
		{
			get {
				return privateKey;
			}
		}
	}
}

