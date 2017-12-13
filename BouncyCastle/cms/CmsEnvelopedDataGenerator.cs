using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    ///  General class for generating a CMS enveloped-data message.
    /// </summary>
    public class CmsEnvelopedDataGenerator : CmsEnvelopedGenerator
    {
        /**
         * base constructor
         */
        public CmsEnvelopedDataGenerator()
        {
        }

        private CmsEnvelopedData doGenerate(
            ICmsTypedData content,
            ICipherBuilderWithKey<AlgorithmIdentifier> contentEncryptor)
        {
            Asn1EncodableVector recipientInfos = new Asn1EncodableVector();
            AlgorithmIdentifier encAlgId;
            Asn1OctetString encContent;

            MemoryOutputStream bOut = new MemoryOutputStream();

            try
            {
                ICipher cOut = contentEncryptor.BuildCipher(bOut);

                content.Write(cOut.Stream);

                cOut.Stream.Close();
            }
            catch (IOException e)
            {
                throw new CmsException(e.Message, e);
            }

            byte[] encryptedContent = bOut.ToArray();

            encAlgId = contentEncryptor.AlgorithmDetails;

            encContent = new BerOctetString(encryptedContent);

            ISymmetricKey encKey = contentEncryptor.Key;

            for (IEnumerator<IRecipientInfoGenerator> it = recipientInfoGenerators.GetEnumerator(); it.MoveNext();)
            {
                IRecipientInfoGenerator recipient = (IRecipientInfoGenerator)it.Current;

                recipientInfos.Add(recipient.Generate(encKey));
            }

            EncryptedContentInfo eci = new EncryptedContentInfo(
                            content.ContentType,
                            encAlgId,
                            encContent);

            Asn1Set unprotectedAttrSet = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(new Dictionary<string, object>());

                unprotectedAttrSet = new BerSet(attrTable.ToAsn1EncodableVector());
            }

            ContentInfo contentInfo = new ContentInfo(
                    CmsObjectIdentifiers.EnvelopedData,
                    new EnvelopedData(originatorInfo, new DerSet(recipientInfos), eci, unprotectedAttrSet));

            return new CmsEnvelopedData(contentInfo);
        }

        /// <summary>
        /// Generate an enveloped object that contains an CMS Enveloped Data object using the given provider.
        /// </summary>
        /// <param name="content">The content to be encrypted</param>
        /// <param name="contentEncryptorBuilder">The symmetric key based encryptor to encrypt the content with.</param>
        /// <returns>A new CMS EnvelopedData object.</returns>
        public CmsEnvelopedData generate(
            ICmsTypedData content,
            ICipherBuilderWithKey<AlgorithmIdentifier> contentEncryptorBuilder)
        {
            return doGenerate(content, contentEncryptorBuilder);
        }
    }
}
