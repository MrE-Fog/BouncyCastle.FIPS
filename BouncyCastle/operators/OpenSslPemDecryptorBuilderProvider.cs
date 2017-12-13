using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;
using System;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Provider class for OpenSSL PEM decryptors.
    /// </summary>
    public class OpenSslPemDecryptorBuilderProvider : IDecryptorBuilderProvider<DekInfo>
    {
        private readonly char[] password;

        /// <summary>
        /// Base construcor.
        /// </summary>
        /// <param name="password">password to configure any produced decryptor for.</param>
        public OpenSslPemDecryptorBuilderProvider(char[] password)
        {
            this.password = password;
        }

        /// <summary>
        /// Create a cipher builder configured for our password and the passed in DEK-Info.
        /// </summary>
        /// <param name="algorithmDetails">The DEK-Info describing the cipher and the IV.</param>
        /// <returns>A cipher builder for decryptors.</returns>
        public ICipherBuilder<DekInfo> CreateDecryptorBuilder(DekInfo algorithmDetails)
        {
            return OpenSslUtilities.Crypt(false, password, algorithmDetails.DekAlgName, algorithmDetails.GetIV());
        }
    }
}
