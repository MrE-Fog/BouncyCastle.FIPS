using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a provider to support the dynamic creation of signature verifier factories.
    /// </summary>
    /// <typeparam name="A">Type for the configuration parameters for the verifier this provider produces.</typeparam>
    public interface IVerifierFactoryProvider<A>
	{
        /// <summary>
        /// Return a signature verifier factory for signature algorithm described in the passed in algorithm details object.
        /// </summary>
        /// <param name="algorithmDetails">The details of the signature algorithm verification is required for.</param>
        /// <returns>A new signature verifier factory.</returns>
		IVerifierFactory<A> CreateVerifierFactory (A algorithmDetails);
	}
}

