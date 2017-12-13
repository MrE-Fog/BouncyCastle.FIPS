namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface describing a provider of key wrapper objects.
    /// </summary>
    /// <typeparam name="A">The algorithm details/parameter type for the key wrappers produced.</typeparam>
    internal interface IKeyWrapperProvider<A>
	{
        /// <summary>
        /// Return a new key wrapper for the passed in algorithm details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm details/parameters to use to create the wrapper.</param>
        /// <returns>A new key wrapper.</returns>
        IKeyWrapper<A> CreateKeyWrapper (A algorithmDetails);
	}
}

