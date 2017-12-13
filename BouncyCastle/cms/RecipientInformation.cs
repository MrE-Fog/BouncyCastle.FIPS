using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    public abstract class RecipientInformation
    {
        internal IRecipientID<RecipientInformation> rid;
        internal AlgorithmIdentifier keyEncAlg;
        internal AlgorithmIdentifier messageAlgorithm;
        internal ICmsSecureReadable secureReadable;


        private IAuthAttributesProvider additionalData;

        private byte[] resultMac;
        private RecipientOperator op;

        internal RecipientInformation(
            AlgorithmIdentifier keyEncAlg,
            AlgorithmIdentifier messageAlgorithm,
            ICmsSecureReadable secureReadable,
            IAuthAttributesProvider additionalData)
        {
            this.keyEncAlg = keyEncAlg;
            this.messageAlgorithm = messageAlgorithm;
            this.secureReadable = secureReadable;
        }

        public IRecipientID<RecipientInformation> RecipientID
        {
            get { return rid; }
        }

        public AlgorithmIdentifier KeyEncryptionAlgorithmID
        {
            get { return keyEncAlg; }
        }

        /**
            * Return the content digest calculated during the read of the content if one has been generated. This will
            * only happen if we are dealing with authenticated data and authenticated attributes are present.
            *
            * @return byte array containing the digest.
            */
        public byte[] GetContentDigest()
        {
            /*
            if (secureReadable is CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable)
            {
                return ((CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable)secureReadable).getDigest();
            }
            */
            return null;
        }

        /// <summary>
        /// Return the MAC calculated for the recipient. Note: this call is only meaningful once all
        /// the content has been read.
        /// </summary>
        /// <returns>byte array containing the mac.</returns>
        public byte[] GetMac()
        {
            if (resultMac == null)
            {
                if (op.IsMacBased)
                {
                    if (additionalData != null)
                    {
                        try
                        {
                            Streams.Drain(op.GetStream(new MemoryInputStream(additionalData.AuthAttributes.GetEncoded(Asn1Encodable.Der))));
                        }
                        catch (IOException e)
                        {
                            throw new InvalidOperationException("unable to drain input: " + e.Message, e);
                        }
                    }
                    resultMac = op.GetMac();
                }
            }

            return resultMac;
        }

        /// <summary>
        /// Return the decrypted/encapsulated content in the EnvelopedData after recovering the content
        /// encryption/MAC key using the passed in Recipient.
        /// </summary>
        /// <param name="recipient">Recipient object to use to recover content encryption key</param>
        /// <returns>The content inside the EnvelopedData this RecipientInformation is associated with.</returns>
        public byte[] GetContent(
            IRecipient recipient)
        {
            try
            {
                return Streams.ReadAll(GetContentStream(recipient).ContentStream);
            }
            catch (IOException e)
            {
                throw new CmsException("unable to parse internal stream: " + e.Message, e);
            }
        }

        /// <summary>
        /// Return a CmsTypedStream representing the content in the EnvelopedData after recovering the content
        /// encryption/MAC key using the passed in Recipient.
        /// </summary>
        /// <param name="recipient">Recipient object to use to recover content encryption key</param>
        /// <returns>The content inside the EnvelopedData this RecipientInformation is associated with.</returns>
        public CmsTypedStream GetContentStream(IRecipient recipient)
        {
            op = GetRecipientOperator(recipient);

            if (additionalData != null)
            {
                return new CmsTypedStream(secureReadable.GetInputStream());
            }

            return new CmsTypedStream(op.GetStream(secureReadable.GetInputStream()));
        }

        protected abstract RecipientOperator GetRecipientOperator(IRecipient recipient);
    }
}
