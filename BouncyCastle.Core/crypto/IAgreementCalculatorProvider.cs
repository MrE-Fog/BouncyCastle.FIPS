
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for a provider of key agreement calculators.
    /// </summary>
    /// <typeparam name="A">The algorithm/parameter details type the key agreement calculators are for.</typeparam>
    public interface IAgreementCalculatorProvider<A>
	{
        /// <summary>
        /// Return a key agreement calculator as described in the passed in algorithm details object.
        /// </summary>
        /// <param name="algorithmDetails">The details of the key agreement algorithm is required.</param>
        /// <returns>A new agreement.</returns>
        IAgreementCalculator<A> CreateAgreementCalculator (A algorithmDetails);
	}
}

