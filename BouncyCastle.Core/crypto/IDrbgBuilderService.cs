using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for builders of SecureRandom objects based on DRBGs.
    /// </summary>
    /// <typeparam name="TRand">The type of SecureRandom produced, e.g. FipsSecureRandom</typeparam>
    public interface IDrbgBuilderService<TRand> where TRand : SecureRandom
    {
        /// <summary>
        /// Create a builder for a DRBG that will be seeded using the default entropy source for the module.
        /// </summary>
        /// <returns>A builder for a SecureRandom based on a DRBG.</returns>
        IDrbgBuilder<TRand> FromDefaultEntropy();

        /// <summary>
        /// Create a builder for a DRBG that will be seeded using the passed in entropy source based on
        /// a SecureRandom which should be considered to be prediction resistant or not.
        /// </summary>
        /// <param name="entropySource">A source of entropy for DRBG seeding.</param>
        /// <param name="predictionResistant">true if the entropy source can be considered prediction resistant, false otherwise.</param>
        /// <returns>A builder for a SecureRandom based on a DRBG seeded using entropySource.</returns>
        IDrbgBuilder<TRand> FromEntropySource(SecureRandom entropySource, bool predictionResistant);

        /// <summary>
        /// Create a builder for a DRBG that will be seeded using entropy sources created from the passed in entropy source provider.
        /// </summary>
        /// <param name="entropySourceProvider">A provider of entropy sources.</param>
        /// <returns>A builder for a SecureRandom based on a DRBG seeded using entropy sources from the provider.</returns>
        IDrbgBuilder<TRand> FromEntropySource(IEntropySourceProvider entropySourceProvider);
    }
}
