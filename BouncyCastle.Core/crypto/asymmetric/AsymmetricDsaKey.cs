using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for DSA keys.
    /// </summary>
	public abstract class AsymmetricDsaKey
        : IAsymmetricKey
	{
		private static readonly ISet dsaOids = new HashSet();

		static AsymmetricDsaKey()
		{
			dsaOids.Add(X9ObjectIdentifiers.IdDsa);
			dsaOids.Add(X9ObjectIdentifiers.IdDsaWithSha1);
			dsaOids.Add(OiwObjectIdentifiers.DsaWithSha1);
		}

		private readonly bool approvedModeOnly;
		private readonly Algorithm algorithm;
		private readonly DsaDomainParameters domainParameters;

		internal AsymmetricDsaKey(Algorithm algorithm, DsaDomainParameters domainParameters)
		{
			this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithm = algorithm;
			this.domainParameters = domainParameters;
		}

		internal AsymmetricDsaKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier)
		{
			this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithm = algorithm;
			this.domainParameters = DecodeDomainParameters(algorithmIdentifier);
		}

		private static DsaDomainParameters DecodeDomainParameters(AlgorithmIdentifier algorithmIdentifier)
		{
			if (!dsaOids.Contains(algorithmIdentifier.Algorithm))
				throw new ArgumentException("Unknown algorithm type: " + algorithmIdentifier.Algorithm);

            if (KeyUtils.IsNotNull(algorithmIdentifier.Parameters))
			{
				DsaParameter parameters = DsaParameter.GetInstance(algorithmIdentifier.Parameters);
				return new DsaDomainParameters(parameters.P, parameters.Q, parameters.G);
			}

			return null;
		}
			
		/// <summary>
		/// Return the algorithm this DSA key is for.
		/// </summary>
		/// <value>The key's algorithm.</value>
		public virtual Algorithm Algorithm
		{
			get { return algorithm; }
		}

		/// <summary>
		/// Return the DSA domain parameters associated with this key.
		/// </summary>
		/// <value>The DSA domain parameters for this key.</value>
		public virtual DsaDomainParameters DomainParameters
		{
			get { return domainParameters; }
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();

        internal virtual void CheckApprovedOnlyModeStatus()
		{
			if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
				throw new CryptoUnapprovedOperationError("No access to key in current thread.");
		}
	}
}

