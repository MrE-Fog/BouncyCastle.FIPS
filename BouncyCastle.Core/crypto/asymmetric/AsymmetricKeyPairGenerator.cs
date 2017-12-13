using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for a generator of public/private key pairs.
    /// </summary>
    /// <typeparam name="TParam">Base parameter type.</typeparam>
    /// <typeparam name="TPublic">Type of the public key in the key pair.</typeparam>
    /// <typeparam name="TPrivate">Type of the private key in the key pair.</typeparam>
    public abstract class AsymmetricKeyPairGenerator<TParam, TPublic, TPrivate>: IAsymmetricKeyPairGenerator<TParam, TPublic, TPrivate> where TPublic : IAsymmetricPublicKey where TPrivate : IAsymmetricPrivateKey
    {
		private readonly TParam parameters;

		internal AsymmetricKeyPairGenerator (TParam parameters)
		{
			this.parameters = parameters;
		}

        /// <summary>
        /// Return the parameters associated with this key pair generator.
        /// </summary>
        public TParam Parameters {
			get {
				return parameters;
			}
		}

        /// <summary>
        /// Generate a new key pair in accordance with the generator's parameter set.
        /// </summary>
        /// <returns>A new key pair.</returns>
        public abstract AsymmetricKeyPair<TPublic, TPrivate> GenerateKeyPair ();
	}
}

