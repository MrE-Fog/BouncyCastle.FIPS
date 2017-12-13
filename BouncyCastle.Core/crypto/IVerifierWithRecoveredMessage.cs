
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Extension interface for a verifier which includes a recovered message.
    /// </summary>
	public interface IVerifierWithRecoveredMessage: IVerifier
	{
        /// <summary>
        /// Return the recovered message picked up as a result of verification.
        /// </summary>
        /// <returns>The recovered message found in the verified signature.</returns>
		IRecoveredMessage GetRecoveredMessage();
	}
}

