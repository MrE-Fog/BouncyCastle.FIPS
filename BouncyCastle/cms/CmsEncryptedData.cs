using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    public class CmsEncryptedData
    {
        private ContentInfo contentInfo;
        private EncryptedData encryptedData;

        public CmsEncryptedData(ContentInfo contentInfo)
        {
            this.contentInfo = contentInfo;

            this.encryptedData = EncryptedData.GetInstance(contentInfo.Content);
        }

        public byte[] GetContent(IDecryptorBuilderProvider<AlgorithmIdentifier> inputDecryptorProvider)
        {
            try
            {
                return Streams.ReadAll(GetContentStream(inputDecryptorProvider).ContentStream);
            }
            catch (IOException e)
            {
                throw new CmsException("unable to parse internal stream: " + e.Message, e);
            }
        }

        public CmsTypedStream GetContentStream(IDecryptorBuilderProvider<AlgorithmIdentifier> inputDecryptorProvider)
        {
            try
            {
                EncryptedContentInfo encContentInfo = encryptedData.EncryptedContentInfo;
                ICipherBuilder<AlgorithmIdentifier> decryptorBuilder = inputDecryptorProvider.CreateDecryptorBuilder(encContentInfo.ContentEncryptionAlgorithm);

                MemoryInputStream encIn = new MemoryInputStream(encContentInfo.EncryptedContent.GetOctets());

                ICipher cipher = decryptorBuilder.BuildCipher(encIn);

                return new CmsTypedStream(encContentInfo.ContentType, cipher.Stream);
            }
            catch (Exception e)
            {
                throw new CmsException("unable to create stream: " + e.Message, e);
            }
        }


        /// <summary>
        /// Return the ContentInfo
        /// </summary>
        /// <returns>The underlying ContentInfo object.</returns>
        public ContentInfo ToAsn1Structure()
        {
            return contentInfo;
        }
    }
}
