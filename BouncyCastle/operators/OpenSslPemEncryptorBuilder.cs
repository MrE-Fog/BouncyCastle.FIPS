using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Builder for OpenSSL encryptors, used to encrypt PEM objects.
    /// </summary>
    public class OpenSslPemEncryptorBuilder
    {
        private readonly DekAlgorithm algorithm;

        private SecureRandom random;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The basic DEK-Info describing the cipher.</param>
        public OpenSslPemEncryptorBuilder(DekAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Configure a SecureRandom for this encryptor builder.
        /// </summary>
        /// <param name="random">The SecureRandom to use.</param>
        /// <returns>The current builder instance.</returns>
        public OpenSslPemEncryptorBuilder WithSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        /// <summary>
        /// Create a cipher builder configured for our DEK-Info and the passed in password.
        /// </summary>
        /// <param name="password">The password to key the cipher builder with.</param>
        /// <returns>A cipher builder for encryptors.</returns>
        public ICipherBuilder<DekInfo> Build(char[] password)
        {
            return OpenSslUtilities.Crypt(true, password, algorithm.Name, CreateIV(algorithm));
        }

        private byte[] CreateIV(DekAlgorithm algorithm)
        {
            if (algorithm.Name.EndsWith("ECB"))
            {
                return null;
            }

            byte[] iv;

            if (algorithm.Name.Contains("AES"))
            {
                iv = new byte[16];
            }
            else
            {
                iv = new byte[8];
            }

            if (random != null)
            {
                random.NextBytes(iv);
            }
            else
            {
                CryptoServicesRegistrar.GetSecureRandom().NextBytes(iv);
            }

            return iv;
        }
    }
}
