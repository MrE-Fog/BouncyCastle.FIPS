using Org.BouncyCastle.Security;


namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for authentication parameters with IVs (used with AEAD algorithms).
    /// </summary>
    /// <typeparam name="TParam">Underlying type implementing the interface.</typeparam>
    /// <typeparam name="TAlg">The algorithm marker type.</typeparam>
	public interface IAuthenticationParametersWithIV<out TParam, out TAlg>:IAuthenticationParameters<TParam, TAlg>, IParametersWithIV<TParam, TAlg> where TParam:IParameters<TAlg> where TAlg:Algorithm
	{
		/// <summary>
		/// Return an implementation of the parameters with an IV constructed from the passed in SecureRandom of length ivLen.
		/// </summary>
		/// <returns>A new set of parameters.</returns>
		/// <param name="random">Source of randomness for iv (nonce)</param>
		/// <param name="ivLen">Length of the iv (nonce) in bytes to use with the algorithm.</param>
		TParam WithIV(SecureRandom random, int ivLen);
	}
}

