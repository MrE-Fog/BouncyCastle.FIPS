using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    /**
    * containing class for an CMS Enveloped Data object
    */
    public class CmsEnvelopedData
    {
        internal RecipientInformationStore	recipientInfoStore;
        internal ContentInfo				contentInfo;

        private AlgorithmIdentifier encAlg;
        private Asn1Set unprotectedAttributes;
        private OriginatorInformation originatorInfo;

        public CmsEnvelopedData(
            byte[] envelopedData)
            : this(CmsUtilities.ReadContentInfo(envelopedData))
        {
        }

        public CmsEnvelopedData(
            Stream envelopedData)
            : this(CmsUtilities.ReadContentInfo(envelopedData))
        {
        }

        public CmsEnvelopedData(
            ContentInfo contentInfo)
        {
            this.contentInfo = contentInfo;

            try
            {
                EnvelopedData envData = EnvelopedData.GetInstance(contentInfo.Content);

                if (envData.OriginatorInfo != null)
                {
                    originatorInfo = new OriginatorInformation(envData.OriginatorInfo);
                }

                //
                // read the recipients
                //
                Asn1Set recipientInfos = envData.RecipientInfos;

                //
                // read the encrypted content info
                //
                EncryptedContentInfo encInfo = envData.EncryptedContentInfo;
                this.encAlg = encInfo.ContentEncryptionAlgorithm;
                CmsReadable readable = new CmsProcessableByteArray(encInfo.EncryptedContent.GetOctets());
                ICmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsEnvelopedSecureReadable(
                    this.encAlg, readable);

                //
                // build the RecipientInformationStore
                //
                this.recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(
                    recipientInfos, this.encAlg, secureReadable);

                this.unprotectedAttributes = envData.UnprotectedAttrs;
            }
            catch (Exception e)
            {
                throw new CmsException("malformed content", e);
            }
        }

		public AlgorithmIdentifier EncryptionAlgorithmID
		{
			get { return encAlg; }
		}

		/**
        * return the object identifier for the content encryption algorithm.
        */
        public string EncryptionAlgOid
        {
            get { return encAlg.Algorithm.Id; }
        }

		/**
        * return a store of the intended recipients for this message
        */
        public RecipientInformationStore GetRecipientInfos()
        {
            return recipientInfoStore;
        }

        /// <summary>
        /// Return the underlying ASN.1 structure for this object.
        /// </summary>
        /// <returns>A ContentInfo object.</returns>
        public ContentInfo ToAsn1Structure()
        {
            return this.contentInfo;
        }

        /**
        * return a table of the unprotected attributes indexed by
        * the OID of the attribute.
        */
        public Asn1.Cms.AttributeTable GetUnprotectedAttributes()
        {
            if (unprotectedAttributes == null)
                return null;

			return new Asn1.Cms.AttributeTable(unprotectedAttributes);
        }

		/**
        * return the ASN.1 encoded representation of this object.
        */
        public byte[] GetEncoded()
        {
			return contentInfo.GetEncoded();
        }
    }
}
