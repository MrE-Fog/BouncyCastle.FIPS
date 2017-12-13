
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for MAC factory objects.
    /// </summary>
    public interface IMacFactoryService
    {
        /// <summary>
        /// Create a MAC factory configured using the algorithmDetails parameter.
        /// </summary>
        /// <typeparam name="A">The parameter type associated with algorithmDetails</typeparam>
        /// <param name="algorithmDetails">The configuration parameters for the returned MAC factory.</param>
        /// <returns>A new MAC factory.</returns>
        IMacFactory<A> CreateMacFactory<A>(A algorithmDetails) where A : IAuthenticationParameters<A, Algorithm>;
    }
}
