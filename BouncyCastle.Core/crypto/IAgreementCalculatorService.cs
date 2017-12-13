
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a service to support the creation of key agreement calculators.
    /// </summary>
    public interface IAgreementCalculatorService
    {
        /// <summary>
        /// Return a key agreement calculator as described in the passed in algorithm details object.
        /// </summary>
        /// <typeparam name="A">The type of the details for the key agreement algorithm to be produced.</typeparam>
        /// <param name="algorithmDetails">The details of the key agreement algorithm is required.</param>
        /// <returns>A new agreement.</returns>
        IAgreementCalculator<A> CreateAgreementCalculator<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
