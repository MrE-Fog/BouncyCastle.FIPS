using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Interface for builders of SecureRandom objects based on DRBGs.
    /// </summary>
    /// <typeparam name="TRand">The type of SecureRandom produced, e.g. FipsSecureRandom</typeparam>
    public interface IDrbgBuilder<TRand> where TRand: SecureRandom
    {
        /// <summary>
        /// Set the personalization string to be used in building the final DRBG.
        /// </summary>
        /// <param name="personalizationString">The personalization string for the final DRBG.</param>
        /// <returns>The current builder.</returns>
        IDrbgBuilder<TRand> SetPersonalizationString(byte[] personalizationString);

        /// <summary>
        /// Set the security strength for the underlying DRBG.
        /// </summary>
        /// <param name="securityStrength"></param>
        /// <returns>The current builder.</returns>
        IDrbgBuilder<TRand> SetSecurityStrength(int securityStrength);

        /// <summary>
        /// Set how many bits of entropy are required for each reseeding of the DRBG.
        /// </summary>
        /// <param name="entropyBitsRequired">Number of entropy bit required on a seed/reseed.</param>
        /// <returns>The current builder.</returns>
        IDrbgBuilder<TRand> SetEntropyBitsRequired(int entropyBitsRequired);

        /// <summary>
        /// Produce a SecureRandom of type TRand based on a DRBG.
        /// </summary>
        /// <param name="nonce">A nonce to use in underlying DRBG initialization.</param>
        /// <param name="predictionResistant">True if the underlying DRBG is to be operated in prediction resistant mode, false otherwise.</param>
        /// <returns>The final SecureRandom built from an underlying DRBG.</returns>
        TRand Build(byte[] nonce, bool predictionResistant);

        /// <summary>
        /// Produce a SecureRandom of type TRand based on a DRBG.
        /// </summary>
        /// <param name="nonce">A nonce to use in underlying DRBG initialization.</param>
        /// <param name="predictionResistant">True if the underlying DRBG is to be operated in prediction resistant mode, false otherwise.</param>
        /// <param name="additionalInput">An additional input parameter for DRBG intialization.</param>
        /// <returns>The final SecureRandom built from an underlying DRBG.</returns>
        TRand Build(byte[] nonce, bool predictionResistant, byte[] additionalInput);
    }
}
