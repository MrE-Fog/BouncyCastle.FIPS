using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for factories that produce stream-based signature verifiers.
    /// </summary>
    /// <typeparam name="A">Configuration parameters type for the verifiers.</typeparam>
    public interface IVerifierFactory<out A>
	{
        /// <summary>The algorithm details object for this verifier.</summary>
        A AlgorithmDetails { get ; }

		/// <summary>
		/// Create a stream calculator for this verifier. The stream
		/// calculator is used for the actual operation of entering the data to be verified
		/// and producing a result which can be used to verify the original signature.
		/// </summary>
		/// <returns>A calculator producing an IVerifier which can verify the signature.</returns>
		IStreamCalculator<IVerifier> CreateCalculator();
	}
}
