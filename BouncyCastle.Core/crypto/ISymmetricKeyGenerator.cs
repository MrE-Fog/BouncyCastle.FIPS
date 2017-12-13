
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for symmetric key generators.
    /// </summary>
    /// <typeparam name="A"></typeparam>
    public interface ISymmetricKeyGenerator<out A> where A : ISymmetricKey
    {
        /// <summary>
        /// Generate a new key.
        /// </summary>
        /// <returns>A new key.</returns>
        A GenerateKey();
    }
}
