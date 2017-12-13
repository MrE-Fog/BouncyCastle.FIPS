using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for parameters with initialization vectors or nonces.
    /// </summary>
    /// <typeparam name="TParam">The type of the implementing parameter.</typeparam>
    /// <typeparam name="TAlg">The algorithm type for the parameters.</typeparam>
    public interface IParametersWithIV<out TParam, out TAlg>:IParameters<TAlg> where TParam: IParameters<TAlg> where TAlg: Algorithm
	{
        /// <summary>
        /// Return the initialization vector associated with this parameter set.
        /// </summary>
        /// <returns>the IV for these parameters.</returns>
        byte[] GetIV();

        /// <summary>
        /// Create a new parameter set with a different IV.
        /// </summary>
        /// <param name="iv">the IV to use.</param>
        /// <returns>A copy of the current parameter set with the new IV.</returns>
        TParam WithIV(byte[] iv);

        /// <summary>
        /// Create a new parameter set with a different IV based on the output of the passed in random.
        /// </summary>
        /// <param name="random">The SecureRandom to use as the source of IV data.</param>
        /// <returns>A copy of the current parameter set with the new IV.</returns>
        TParam WithIV(SecureRandom random);
	}
}

