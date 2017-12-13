
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface describing a provider of key unwrapper objects.
    /// </summary>
    /// <typeparam name="A">The algorithm details/parameter type for the key unwrappers produced.</typeparam>
    public interface IKeyUnwrapperProvider<A>
	{
        /// <summary>
        /// Return a new key unwrapper for the passed in algorithm details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm details/parameters to use to create the unwrapper.</param>
        /// <returns>A new key unwrapper.</returns>
        IKeyUnwrapper<A> CreateKeyUnwrapper (A algorithmDetails);
	}
}

