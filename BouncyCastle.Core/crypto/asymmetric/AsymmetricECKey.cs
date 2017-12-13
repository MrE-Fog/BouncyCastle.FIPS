
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for Elliptic Curve (EC) keys.
    /// </summary>
	public abstract class AsymmetricECKey: IAsymmetricKey
	{
		private readonly bool    approvedModeOnly;
		private readonly Algorithm algorithm;
		private readonly ECDomainParameters domainParameters;

		internal AsymmetricECKey(Algorithm algorithm, ECDomainParameters domainParameters)
		{
			this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithm = algorithm;
			this.domainParameters = domainParameters;
		}

		internal AsymmetricECKey(Algorithm algorithm, IECDomainParametersID domainParameterID): this(algorithm, ECDomainParametersIndex.LookupDomainParameters(domainParameterID))
		{
		}

		internal AsymmetricECKey(Algorithm algorithm, AlgorithmIdentifier algorithmIdentifier): this(algorithm, ECDomainParameters.DecodeCurveParameters(algorithmIdentifier)) 
		{	
		}
			
		/// <summary>
		/// Return the algorithm this Elliptic Curve key is for.
		/// </summary>
		/// <value>The key's algorithm.</value>
		public Algorithm Algorithm
		{
			get {
				if (this is AsymmetricECPrivateKey)
				{
					CheckApprovedOnlyModeStatus();
				}

				return algorithm;
			}
		}
			
		/// <summary>
		/// Return the Elliptic Curve domain parameters associated with this key.
		/// </summary>
		/// <value>The EC domain parameters for the key.</value>
		public ECDomainParameters DomainParameters
		{
			get {
				if (this is AsymmetricECPrivateKey)
				{
					CheckApprovedOnlyModeStatus();
				}

				return domainParameters;
			}
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();

		internal void CheckApprovedOnlyModeStatus()
		{
			if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
			{
				throw new CryptoUnapprovedOperationError("No access to key in current thread.");
			}
		}
	}
}

