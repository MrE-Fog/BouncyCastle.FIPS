using System;

namespace Org.BouncyCastle.Crypto.Internal
{
    /**
     * interface that a public/private key pair generator should conform to.
     */
    internal interface IAsymmetricCipherKeyPairGenerator
    {
        /**
         * intialise the key pair generator.
         *
         * @param the parameters the key pair is to be initialised with.
         */
        void Init(KeyGenerationParameters parameters);

        /**
         * return an AsymmetricCipherKeyPair containing the Generated keys.
         *
         * @return an AsymmetricCipherKeyPair containing the Generated keys.
         */
        AsymmetricCipherKeyPair GenerateKeyPair();
    }
}
