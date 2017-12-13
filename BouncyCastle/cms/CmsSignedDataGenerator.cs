using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Collections.Generic;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /**
     * general class for generating a pkcs7-signature message.
     * <p>
     * A simple example of usage.
     *
     * <pre>
     *      IX509Store certs...
     *      IX509Store crls...
     *      CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
     *
     *      gen.AddSigner(privKey, cert, CmsSignedGenerator.DigestSha1);
     *      gen.AddCertificates(certs);
     *      gen.AddCrls(crls);
     *
     *      CmsSignedData data = gen.Generate(content);
     * </pre>
	 * </p>
     */
    public class CmsSignedDataGenerator
        : CmsSignedGenerator
    {
		private static readonly CmsSignedHelper Helper = CmsSignedHelper.Instance;

		private readonly IList signerInfs = Platform.CreateArrayList();

        /// <summary>
        /// Base constructor.
        /// </summary>
		public CmsSignedDataGenerator()
        {
        }

		/**
        * generate a signed object that for a CMS Signed Data object
        */
        public CmsSignedData Generate(
            ICmsTypedData content)
        {
            return Generate(content, false);
        }

        /**
        * generate a signed object that for a CMS Signed Data
        * object  - if encapsulate is true a copy
        * of the message will be included in the signature. The content type
        * is set according to the OID represented by the string signedContentType.
        */
        public CmsSignedData Generate(
			// FIXME Avoid accessing more than once to support CmsProcessableInputStream
            ICmsTypedData	content,
            bool			encapsulate)
        {
            // TODO
            //        if (signerInfs.isEmpty())
            //        {
            //            /* RFC 3852 5.2
            //             * "In the degenerate case where there are no signers, the
            //             * EncapsulatedContentInfo value being "signed" is irrelevant.  In this
            //             * case, the content type within the EncapsulatedContentInfo value being
            //             * "signed" MUST be id-data (as defined in section 4), and the content
            //             * field of the EncapsulatedContentInfo value MUST be omitted."
            //             */
            //            if (encapsulate)
            //            {
            //                throw new IllegalArgumentException("no signers, encapsulate must be false");
            //            }
            //            if (!DATA.equals(eContentType))
            //            {
            //                throw new IllegalArgumentException("no signers, eContentType must be id-data");
            //            }
            //        }
            //
            //        if (!DATA.equals(eContentType))
            //        {
            //            /* RFC 3852 5.3
            //             * [The 'signedAttrs']...
            //             * field is optional, but it MUST be present if the content type of
            //             * the EncapsulatedContentInfo value being signed is not id-data.
            //             */
            //            // TODO signedAttrs must be present for all signers
            //        }

            Asn1EncodableVector digestAlgs = new Asn1EncodableVector();
            Asn1EncodableVector signerInfos = new Asn1EncodableVector();

            _digests.Clear();  // clear the current preserved digest state

            //
            // add the precalculated SignerInfo objects.
            //
            for (IEnumerator it = _signers.GetEnumerator(); it.MoveNext();)
            {
                SignerInformation signer = (SignerInformation)it.Current;
                digestAlgs.Add(CmsUtilities.fixAlgID(signer.DigestAlgorithmID));

                // TODO Verify the content type and calculated digest match the precalculated SignerInfo
                signerInfos.Add(signer.ToAsn1Structure());
            }

            //
            // add the SignerInfo objects
            //
            DerObjectIdentifier contentTypeOID = content.ContentType;

            Asn1OctetString octs = null;

            if (content.GetContent() != null)
            {
                MemoryOutputStream bOut = null;

                if (encapsulate)
                {
                    bOut = new MemoryOutputStream();
                }

                Stream cOut = CmsUtilities.attachSignersToOutputStream(_signerGens, bOut);

                // Just in case it's unencapsulated and there are no signers!
                cOut = CmsUtilities.getSafeOutputStream(cOut);

                try
                {
                    content.Write(cOut);

                    cOut.Close();
                }
                catch (IOException e)
                {
                    throw new CmsException("data processing exception: " + e.Message, e);
                }

                if (encapsulate)
                {
                    octs = new BerOctetString(bOut.ToArray());
                }
            }

            for (IEnumerator it = _signerGens.GetEnumerator(); it.MoveNext();)
            {
                SignerInfoGenerator sGen = (SignerInfoGenerator)it.Current;
                SignerInfo inf = sGen.Generate(contentTypeOID);

                digestAlgs.Add(inf.DigestAlgorithm);
                signerInfos.Add(inf);

                byte[] calcDigest = sGen.getCalculatedDigest();

                if (calcDigest != null)
                {
                    _digests.Add(inf.DigestAlgorithm.Algorithm.Id, calcDigest);
                }
            }

            Asn1Set certificates = null;

            if (_certs.Count != 0)
            {
                certificates = CmsUtilities.CreateBerSetFromList(_certs);
            }

            Asn1Set certrevlist = null;

            if (_crls.Count != 0)
            {
                certrevlist = CmsUtilities.CreateBerSetFromList(_crls);
            }

            ContentInfo encInfo = new ContentInfo(contentTypeOID, octs);

            SignedData sd = new SignedData(
                                     new DerSet(digestAlgs),
                                     encInfo,
                                     certificates,
                                     certrevlist,
                                     new DerSet(signerInfos));

            ContentInfo contentInfo = new ContentInfo(
                CmsObjectIdentifiers.SignedData, sd);

            return new CmsSignedData(content, contentInfo);
        }

		/**
		* generate a set of one or more SignerInformation objects representing counter signatures on
		* the passed in SignerInformation object.
		*
		* @param signer the signer to be countersigned
		* @param sigProvider the provider to be used for counter signing.
		* @return a store containing the signers.
		*/
		public SignerInformationStore GenerateCounterSigners(
			SignerInformation signer)
		{
			return this.Generate(new CmsProcessableByteArray(null, signer.GetSignature()), false).GetSignerInfos();
		}
	}
}
