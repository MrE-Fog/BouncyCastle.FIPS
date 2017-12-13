
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Provider interface for providers of XOF factory objects.
    /// </summary>
    /// <typeparam name="A">Type for the configuration parameters for the verifier this provider produces.</typeparam>
	public interface IXofFactoryProvider<A>
	{
        /// <summary>
        /// Create a new XOF factory using the passed in parameters.
        /// </summary>
        /// <param name="algorithmDetails">Configuration parameters for the XOF factory.</param>
        /// <returns>A new factory for producing XOFs</returns>
		IXofFactory<A> CreateXofFactory (A algorithmDetails);
	}
}

