using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for RSA keys.
    /// <para>
    /// Note: the module attempts to prevent accidental recent use of RSA keys for signing and encryption purposes by associating
    /// a specific usage with a modulus. If the module is not running in approved mode this behavior can be overridden by
    /// setting the system property "Org.BouncyCastle.Rsa.AllowMultiUse" to "true".
    /// </para>
    /// </summary>
    public abstract class AsymmetricRsaKey
        : IAsymmetricKey
	{
		/// <summary>
		/// Specific RSA key usages.
		/// </summary>
		public enum Usage
		{
			/// <summary>No key usage defined yet.</summary>
			Undefined,
			/// <summary>Key usage signing or verification.</summary>
			SignOrVerify,
			/// <summary>Key usage encryption or decryption.</summary>
			EncryptOrDecrypt,
		}

		protected static readonly AlgorithmIdentifier DEF_ALG_ID = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
		private static readonly ISet rsaOids = new HashSet();

		static AsymmetricRsaKey()
		{
			rsaOids.Add(PkcsObjectIdentifiers.RsaEncryption);
			rsaOids.Add(X509ObjectIdentifiers.IdEARsa);
			rsaOids.Add(PkcsObjectIdentifiers.IdRsaesOaep);
			rsaOids.Add(PkcsObjectIdentifiers.IdRsassaPss);
			rsaOids.Add(PkcsObjectIdentifiers.IdRsaKem);
		}

		private readonly bool approvedModeOnly;
		private readonly KeyMarker keyMarker;

		private Algorithm algorithm;
		private BigInteger modulus;

		protected readonly AlgorithmIdentifier rsaAlgIdentifier;

		internal AsymmetricRsaKey(Algorithm algorithm, BigInteger modulus)
		{
			this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithm = algorithm;
			this.keyMarker = GetKeyMarker(modulus);
			this.modulus = keyMarker.modulus;
			this.rsaAlgIdentifier = DEF_ALG_ID;
		}

		internal AsymmetricRsaKey(Algorithm algorithm, AlgorithmIdentifier rsaAlgIdentifier, BigInteger modulus)
		{
			DerObjectIdentifier keyAlgorithm = rsaAlgIdentifier.Algorithm;
			if (!rsaOids.Contains(keyAlgorithm))
				throw new ArgumentException("Unknown algorithm type: " + keyAlgorithm);

            this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithm = algorithm;
			this.rsaAlgIdentifier = rsaAlgIdentifier;
			this.keyMarker = GetKeyMarker(modulus);
			this.modulus = keyMarker.modulus;

			if (keyAlgorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
			{
				keyMarker.CanBeUsed(Usage.SignOrVerify);
			}
			else if (keyAlgorithm.Equals(PkcsObjectIdentifiers.IdRsaesOaep))
			{
				keyMarker.CanBeUsed(Usage.EncryptOrDecrypt);
			}
		}
			
		/// <summary>
		/// Return the algorithm this RSA key is for.
		/// </summary>
		/// <value>The key's algorithm.</value>
		public virtual Algorithm Algorithm
		{
			get { return algorithm; }
		}

		/// <summary>
		/// Return the modulus for this RSA key.
		/// </summary>
		/// <value>The key's modulus.</value>
		public virtual BigInteger Modulus
		{
			get { return modulus; }
		}

		/// <summary>
		/// Check to see if a key can be used for a specific usage. Essentially this will return false if
		/// the modulus is associated with a different usage already. The system property
        /// "Org.BouncyCastle.Rsa.AllowMultiUse" can be set to "true" to override this check.
		/// </summary>
		/// <returns><c>true</c> if the modulus is already associated with the usage, or has not being used already; otherwise, <c>false</c>.</returns>
		/// <param name="usage">Usage for the RSA key.</param>
		public bool CanBeUsed(Usage usage)
		{
            return Properties.IsOverrideSet("Org.BouncyCastle.Rsa.AllowMultiUse")
                || keyMarker.CanBeUsed(usage);
        }

        internal virtual void Zeroize()
		{
			this.algorithm = null;
			this.modulus = null;
		}

        internal virtual void CheckApprovedOnlyModeStatus()
		{
			if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
				throw new CryptoUnapprovedOperationError("No access to key in current thread.");
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();

        private static IDictionary<BigInteger, WeakReference<KeyMarker>> markers = new Dictionary<BigInteger, WeakReference<KeyMarker>>();

        // register a modulus in the cache - we do this for generated ones to avoid the need
        // to revalidate on key construction.
        internal static void RegisterModulus(BigInteger modulus)
        {
            GetKeyMarker(modulus);
        }

        private static KeyMarker GetKeyMarker(BigInteger modulus)
        {
            lock (markers)
            {
                KeyMarker marker;
                WeakReference<KeyMarker> existingRef;
                if (markers.TryGetValue(modulus, out existingRef))
                {
                    if (existingRef.TryGetTarget(out marker))
                    {
                        return marker;
                    }

                    marker = new KeyMarker(modulus);
                    existingRef.SetTarget(marker);
                }
                else
                {
                    marker = new KeyMarker(modulus);
                    markers.Add(modulus, new WeakReference<KeyMarker>(marker));
                }

                return marker;
            }
        }

        private static void KeyMarkerFinalized(BigInteger modulus)
        {
            lock (markers)
            {
                WeakReference<KeyMarker> existingRef;
                if (markers.TryGetValue(modulus, out existingRef))
                {
                    KeyMarker existingMarker;
                    if (!existingRef.TryGetTarget(out existingMarker))
                    {
                        markers.Remove(modulus);
                    }
                }
            }
        }

        internal static bool IsAlreadySeen(BigInteger modulus)
		{
            lock (markers) return markers.ContainsKey(modulus);
		}

        private class KeyMarker
		{
			internal readonly BigInteger modulus;
            private Usage keyUsage = Usage.Undefined;

            internal KeyMarker(BigInteger modulus)
			{
				this.modulus = modulus;
			}

            ~KeyMarker()
            {
                KeyMarkerFinalized(modulus);
            }

            internal bool CanBeUsed(Usage usage)
			{
                lock (this)
                {
				    if (keyUsage == Usage.Undefined)
                    {
					    keyUsage = usage;
				    }
				    return keyUsage == usage;
                }
            }
        }
	}
}
