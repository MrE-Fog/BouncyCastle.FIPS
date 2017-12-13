using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
    public class OpenSslEncryptedObject
    {
        private readonly string mType;
        private readonly string dekInfo;
        private readonly byte[] keyBytes;
        private readonly PemKeyPairParser parser;

        internal OpenSslEncryptedObject(string type, string dekInfo, byte[] keyBytes, PemKeyPairParser parser)
        {
            this.mType = type;
            this.dekInfo = dekInfo;
            this.keyBytes = keyBytes;
            this.parser = parser;
        }

        public string Type
        {
            get { return mType;  }
        }

        public object Decrypt(IDecryptorBuilderProvider<DekInfo> keyDecryptorProvider)
        {
            try
            {
                ICipherBuilder<DekInfo> decryptorBuilder = keyDecryptorProvider.CreateDecryptorBuilder(new DekInfo(dekInfo));

                MemoryInputStream bOut = new MemoryInputStream(keyBytes);
                ICipher decryptor = decryptorBuilder.BuildCipher(bOut);

                using (var stream = decryptor.Stream)
                {
                    return parser.Parse(Streams.ReadAll(stream));
                }
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new OpenSslPemParsingException("exception processing key pair: " + e.Message, e);
            }
        }
    }
}
