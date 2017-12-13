namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface describing a provider of digest factory objects.
    /// </summary>
    /// <typeparam name="A">The algorithm details/parameter type for the digest factories produced.</typeparam>
	public interface IDigestFactoryProvider<A>
	{
        /// <summary>
        /// Return a new digest factory for the passed in algorithm details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm details/parameters to use to create the factory.</param>
        /// <returns>A new digest factory.</returns>
        IDigestFactory<A> CreateDigestFactory (A algorithmDetails);
	}
}

