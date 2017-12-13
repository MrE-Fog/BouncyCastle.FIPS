
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a calculator used in key agreement.
    /// </summary>
    /// <typeparam name="A">The algorithm/parameter details type the agreement calculators are for.</typeparam>
	public interface IAgreementCalculator<out A>
	{
		/// <summary>The algorithm details object for calculators made by this factory.</summary>
		A AlgorithmDetails { get ; }

		/// <summary>
		/// Calculate the agreement using the passed in public key.
		/// </summary>
		/// <param name="publicKey">The public key of the other party.</param>
		/// <returns>A byte array containing the agreed value.</returns>
		byte[] Calculate(IAsymmetricPublicKey publicKey);
	}
}

