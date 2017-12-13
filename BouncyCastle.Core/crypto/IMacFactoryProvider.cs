namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface describing a provider of MAC calculator factory objects.
    /// </summary>
    /// <typeparam name="A">The algorithm details/parameter type for the MAC calculator factories produced.</typeparam>
	public interface IMacFactoryProvider<A>
	{
        /// <summary>
        /// Return a new MAC calculator factory for the passed in algorithm details.
        /// </summary>
        /// <param name="algorithmDetails">The algorithm details/parameters to use to create the factory.</param>
        /// <returns>A new MAC calculator factory.</returns>
		IMacFactory<A> CreateMacFactory(A algorithmDetails);
	}
}
