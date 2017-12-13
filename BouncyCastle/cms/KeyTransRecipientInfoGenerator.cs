using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System;

namespace Org.BouncyCastle.Cms
{
    public abstract class KeyTransRecipientInfoGenerator: IRecipientInfoGenerator
    {
        private IssuerAndSerialNumber issuerAndSerial;
        private byte[] subjectKeyIdentifier;

        protected KeyTransRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial)
        {
            this.issuerAndSerial = issuerAndSerial;
        }

        protected KeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier)
        {
            this.subjectKeyIdentifier = subjectKeyIdentifier;
        }

        public RecipientInfo Generate(ISymmetricKey contentEncryptionKey)
        {
            byte[] encryptedKeyBytes;
            try
            {
                encryptedKeyBytes = GenerateWrappedKey(contentEncryptionKey);
            }
            catch (Exception e)
            {
                throw new CmsException("exception wrapping content key: " + e.Message, e);
            }

            RecipientIdentifier recipId;
            if (issuerAndSerial != null)
            {
                recipId = new RecipientIdentifier(issuerAndSerial);
            }
            else
            {
                recipId = new RecipientIdentifier(new DerOctetString(subjectKeyIdentifier));
            }

            return new RecipientInfo(new KeyTransRecipientInfo(recipId, AlgorithmDetails,
                new DerOctetString(encryptedKeyBytes)));
        }

        protected abstract AlgorithmIdentifier AlgorithmDetails { get; }

        protected abstract byte[] GenerateWrappedKey(ISymmetricKey contentKey);
    }
}
