using Org.BouncyCastle.Crypto.Asymmetric;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a generator of public/private key pairs.
    /// </summary>
    /// <typeparam name="TParam">Base parameter type.</typeparam>
    /// <typeparam name="TPublic">Type of the public key in the key pair.</typeparam>
    /// <typeparam name="TPrivate">Type of the private key in the key pair.</typeparam>
    public interface IAsymmetricKeyPairGenerator<out TParam, TPublic, TPrivate> where TPublic : IAsymmetricPublicKey where TPrivate : IAsymmetricPrivateKey
    {
        /// <summary>
        /// Return the parameters associated with this key pair generator.
        /// </summary>
        TParam Parameters { get; }

        /// <summary>
        /// Generate a new key pair in accordance with the generator's parameter set.
        /// </summary>
        /// <returns>A new key pair.</returns>
        AsymmetricKeyPair<TPublic, TPrivate> GenerateKeyPair();
    }
}
