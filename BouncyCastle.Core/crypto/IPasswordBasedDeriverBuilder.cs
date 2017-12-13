namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a builder of password derivers.
    /// </summary>
    /// <typeparam name="A">Type for the deriver builder's configuration parameters.</typeparam>
    public interface IPasswordBasedDeriverBuilder<A>
    {
        /// <summary>
        /// Return a new builder configured with the passed in digest as the pseudo random function for derivers produced.
        /// </summary>
        /// <param name="digestAlgorithm">The digest algorithm to use as a PRF.</param>
        /// <returns>A new builder.</returns>
        IPasswordBasedDeriverBuilder<A> WithPrf(DigestAlgorithm digestAlgorithm);

        /// <summary>
        /// Return a new builder configured with the passed in salt for derivers it builds.
        /// </summary>
        /// <param name="salt">The salt to use with the PRF.</param>
        /// <returns>A new builder.</returns>
        IPasswordBasedDeriverBuilder<A> WithSalt(byte[] salt);

        /// <summary>
        /// Return a new builder configured with the passed in iteration count for derivers it builds. 
        /// </summary>
        /// <param name="iterationCount">The iteration count to use with the PRF.</param>
        /// <returns>A new builder.</returns>
        IPasswordBasedDeriverBuilder<A> WithIterationCount(int iterationCount);

        /// <summary>
        /// Build a key deriver based on the current configuration.
        /// </summary>
        /// <returns>a new password based key deriver.</returns>
        IPasswordBasedDeriver<A> Build();
    }
}
