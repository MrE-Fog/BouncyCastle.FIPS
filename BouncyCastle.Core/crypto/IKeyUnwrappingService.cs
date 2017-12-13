namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for key unwrappers.
    /// </summary>
    public interface IKeyUnwrappingService
    {
        /// <summary>
        /// Create a key unwrapper configured using the algorithmDetails parameter.
        /// </summary>
        /// <typeparam name="A">The parameter type associated with algorithmDetails</typeparam>
        /// <param name="algorithmDetails">The configuration parameters for the returned key unwrapper.</param>
        /// <returns>A new key unwrapper.</returns>
        IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
