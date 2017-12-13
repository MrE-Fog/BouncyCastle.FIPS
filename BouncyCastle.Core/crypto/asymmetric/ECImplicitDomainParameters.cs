using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	/// <summary>
	/// Extension class that identifies this domain parameter set as being the ImplicitlyCa domain
	/// parameters for this JVM.
	/// </summary>
	public class ECImplicitDomainParameters: ECDomainParameters
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="domainParameters">The ImplicitlyCa domain parameters.</param>
		public ECImplicitDomainParameters(ECDomainParameters domainParameters): base(domainParameters.Curve, domainParameters.G, domainParameters.N, domainParameters.H, domainParameters.GetSeed())
		{
			
		}
	}
}

