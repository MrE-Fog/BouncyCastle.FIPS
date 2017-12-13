namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for key wrappers.
    /// </summary>
    public interface IKeyWrappingService
    {
        /// <summary>
        /// Create a make factory configured using the algorithmDetails parameter.
        /// </summary>
        /// <typeparam name="A">The parameter type associated with algorithmDetails</typeparam>
        /// <param name="algorithmDetails">The configuration parameters for the returned key wrapper.</param>
        /// <returns>A new key wrapper.</returns>
        IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
