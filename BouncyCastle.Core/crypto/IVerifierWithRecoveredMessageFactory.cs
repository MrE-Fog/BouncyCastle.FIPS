
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Factory for verifiers which include recovered messages.
    /// </summary>
	public interface IVerifierWithRecoveredMessageFactory
	{
		/// <summary>
		/// Create a stream calculator for this signature calculator. The stream
		/// calculator is used for the actual operation of entering the data to be verified
		/// against a pre-existing signature.
		/// </summary>
		/// <returns>A calculator producing an IVerifierWithRecoveredMessage with a verifier and the recovered message in it.</returns>
		IStreamCalculator<IVerifierWithRecoveredMessage> CreateCalculatorWithRecoveredMessage();
	}
}

