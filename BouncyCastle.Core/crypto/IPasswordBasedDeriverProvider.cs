
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a provider to support the dynamic creation of password based derivers.
    /// </summary>
    /// <typeparam name="A">Type for configuration parameters used to create derivers produced by this provider.</typeparam>
    public interface IPasswordBasedDeriverProvider<A>
	{
		/// <summary>
		/// Return a password based deriver for the algorithm details passed in.
		/// </summary>
		/// <param name="algorithmDetails">The details of the password to key derivation algorithm the deriver is for.</param>
		/// <returns>A new password based deriver.</returns>
		IPasswordBasedDeriver<A> CreateDeriver (A algorithmDetails);
	}
}

