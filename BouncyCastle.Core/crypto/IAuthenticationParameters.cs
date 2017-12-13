
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for authentication parameters (used with MAC/HMAC algorithms).
    /// </summary>
    /// <typeparam name="TParam">Underlying type implementing the interface.</typeparam>
    /// <typeparam name="TAlg">The algorithm marker type.</typeparam>
	public interface IAuthenticationParameters<out TParam, out TAlg>:IParameters<TAlg> where TAlg:Algorithm
	{
		/// <summary>
		/// Return the size of the MAC these parameters are for.
		/// </summary>
		/// <value>The MAC size in bits.</value>
		int MacSizeInBits { get; }

		/// <summary>
		/// Create a new parameter set with the specified MAC size associated with it.
		/// </summary>
		/// <returns>The new parameter set.</returns>
		/// <param name="macSizeInBits">Mac size in bits.</param>
		TParam WithMacSize(int macSizeInBits);
	}
}

