namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for key material generators used in key agreement.
    /// </summary>
    public interface IKMGenerator
    {
        /// <summary>
        /// Generate key material using the passed in agreed value.
        /// </summary>
        /// <param name="agreed">The agreed value calculated from key agreement.</param>
        /// <returns>The key material derived from agreed and any internal parameters.</returns>
        byte[] Generate(byte[] agreed);
    }
}
