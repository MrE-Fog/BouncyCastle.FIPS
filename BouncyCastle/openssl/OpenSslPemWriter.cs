

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Utilities.IO.Pem;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>
    /// Writer for OpenSSL style PEM objects.
    /// </summary>
    public class OpenSslPemWriter : PemWriter
    {
        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="writer">The underlying TextWriter to output PEM data to.</param>
        public OpenSslPemWriter(TextWriter writer) : base(writer)
        {

        }

        /// <summary>
        /// Encode the passed in object and write it in PEM format.
        /// </summary>
        /// <param name="obj">The object to be encoded.</param>
        public void WriteObject(object obj)
        {
            WriteObject(obj, null);
        }

        /// <summary>
        /// Encode and encrypt the passed in object and write it in PEM format.
        /// </summary>
        /// <param name="obj">The object to be encoded and encrypted.</param>
        /// <param name="encryptor">The PEM encryptor to use.</param>
        public void WriteObject(object obj, ICipherBuilder<DekInfo> encryptor)
        {
            try
            {
                base.WriteObject(new MiscPemGenerator(obj, encryptor));
            }
            catch (PemGenerationException e)
            {
                if (e.InnerException is IOException)
                {
                    throw e.InnerException;
                }

                throw e;
            }
        }
    }
}
