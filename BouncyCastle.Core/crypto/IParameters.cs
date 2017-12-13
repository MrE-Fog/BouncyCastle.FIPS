namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for operator parameters.
    /// </summary>
    /// <typeparam name="TAlg">The algorithm type for the parameters.</typeparam>
    public interface IParameters<out TAlg> where TAlg: Algorithm
	{
		/// <summary>
		/// Return the algorithm these parameters are associated with.
		/// </summary>
		/// <value>The algorithm these parameters are for.</value>
		TAlg Algorithm { get; }
	}
}

