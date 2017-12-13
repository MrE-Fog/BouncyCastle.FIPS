
namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// A cipher builder that can also return the key it was initialized with.
    /// </summary>
    /// <typeparam name="A">The algorithm details parameter type.</typeparam>
    public interface ICipherBuilderWithKey<out A>: ICipherBuilder<A>
    {
        /// <summary>
        /// Return the key we were initialized with.
        /// </summary>
        ISymmetricKey Key { get; }
    }
}
