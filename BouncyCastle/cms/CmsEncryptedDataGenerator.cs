

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    public class CmsEncryptedDataGenerator: CmsEncryptedGenerator
    {
        /**
   * base constructor
   */
        public CmsEncryptedDataGenerator()
        {
        }

        private CmsEncryptedData doGenerate(
            ICmsTypedData content,
            ICipherBuilder<AlgorithmIdentifier> contentEncryptor)
        {
            AlgorithmIdentifier encAlgId;
            Asn1OctetString encContent;

            MemoryOutputStream bOut = new MemoryOutputStream();

            try
            {
                ICipher cipher = contentEncryptor.BuildCipher(bOut);

                content.Write(cipher.Stream);

                cipher.Stream.Close();
            }
            catch (IOException)
            {
                throw new CmsException("");
            }

            byte[] encryptedContent = bOut.ToArray();

            encAlgId = contentEncryptor.AlgorithmDetails;

            encContent = new BerOctetString(encryptedContent);

            EncryptedContentInfo eci = new EncryptedContentInfo(
                            content.ContentType,
                            encAlgId,
                            encContent);

            Asn1Set unprotectedAttrSet = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(new Dictionary<string,object>());

                unprotectedAttrSet = new BerSet(attrTable.ToAsn1EncodableVector());
            }

            ContentInfo contentInfo = new ContentInfo(
                    CmsObjectIdentifiers.EncryptedData,
                    new EncryptedData(eci, unprotectedAttrSet));

            return new CmsEncryptedData(contentInfo);
        }

        /**
         * generate an encrypted object that contains an Cms Encrypted Data structure.
         *
         * @param content the content to be encrypted
         * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
         */
        public CmsEncryptedData generate(
            ICmsTypedData content,
            ICipherBuilder<AlgorithmIdentifier> contentEncryptor)
        {
            return doGenerate(content, contentEncryptor);
        }
    }
}
