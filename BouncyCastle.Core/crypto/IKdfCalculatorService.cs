namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for KDF calculators.
    /// </summary>
    public interface IKdfCalculatorService
    {
        /// <summary>
        /// Create a KDF calculator configured using the algorithmDetails parameter.
        /// </summary>
        /// <typeparam name="A">The parameter type associated with algorithmDetails</typeparam>
        /// <param name="algorithmDetails">The configuration parameters for the returned KDF calculator.</param>
        /// <returns>A new KDF calculator.</returns>
        IKdfCalculator<A> CreateCalculator<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
