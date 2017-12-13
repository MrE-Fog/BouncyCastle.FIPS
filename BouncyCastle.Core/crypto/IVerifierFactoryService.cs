
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for creating verifier factory objects.
    /// </summary>
    public interface IVerifierFactoryService
    {
        /// <summary>
        /// Return a new verifier factory configured according to the contents of algorithmDetails.
        /// </summary>
        /// <typeparam name="A">The type of the configuration parameters.</typeparam>
        /// <param name="algorithmDetails">The configuration parameters to use to configure the factory.</param>
        /// <returns>A new verifier factory.</returns>
        IVerifierFactory<A> CreateVerifierFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
