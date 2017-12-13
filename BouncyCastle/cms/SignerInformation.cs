using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Collections.Generic;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// An expanded SignerInfo block from a CMS Signed message
    /// </summary>
    public class SignerInformation
    {
        private static readonly CmsSignedHelper Helper = CmsSignedHelper.Instance;

        private SignerID sid;
        private Asn1.Cms.SignerInfo info;
        private AlgorithmIdentifier digestAlgorithm;
        private AlgorithmIdentifier encryptionAlgorithm;
        private readonly Asn1Set signedAttributeSet;
        private readonly Asn1Set unsignedAttributeSet;
        private ICmsTypedData content;
        private byte[] signature;
        private DerObjectIdentifier contentType;
        private byte[] resultDigest;

        // Derived
        private Asn1.Cms.AttributeTable signedAttributeTable;
        private Asn1.Cms.AttributeTable unsignedAttributeTable;
        private readonly bool isCounterSignature;

        internal SignerInformation(
            Asn1.Cms.SignerInfo info,
            DerObjectIdentifier contentType,
            ICmsTypedData content,
            byte[] digest)
        {
            this.info = info;

            this.contentType = contentType;
            this.isCounterSignature = contentType == null;

            try
            {
                SignerIdentifier s = info.SignerID;

                if (s.IsTagged)
                {
                    Asn1OctetString octs = Asn1OctetString.GetInstance(s.ID);

                    this.sid = new SignerID(octs.GetEncoded());
                }
                else
                {
                    Asn1.Cms.IssuerAndSerialNumber iAnds =
                        Asn1.Cms.IssuerAndSerialNumber.GetInstance(s.ID);

                    this.sid = new SignerID(iAnds.Name, iAnds.SerialNumber.Value);
                }
            }
            catch (IOException)
            {
                throw new ArgumentException("invalid sid in SignerInfo");
            }

            this.digestAlgorithm = info.DigestAlgorithm;
            this.signedAttributeSet = info.AuthenticatedAttributes;
            this.unsignedAttributeSet = info.UnauthenticatedAttributes;
            this.encryptionAlgorithm = info.DigestEncryptionAlgorithm;
            this.signature = info.EncryptedDigest.GetOctets();

            this.content = content;
            this.resultDigest = digest;
        }

        public bool IsCounterSignature
        {
            get { return isCounterSignature; }
        }

        public DerObjectIdentifier ContentType
        {
            get { return contentType; }
        }

        public SignerID SignerID
        {
            get { return sid; }
        }

        /// <summary>
        /// Return the version number for this objects underlying SignerInfo structure.
        /// </summary>
        public int Version
        {
            get { return info.Version.Value.IntValue; }
        }

        /// <summary>
        /// Return the signature, or digest encryption, algorithm
        /// </summary>
        public AlgorithmIdentifier SignatureAlgorithmID
        {
            get { return encryptionAlgorithm; }
        }

        /// <summary>
        /// Return the digest algorithm details associated with the signature.
        /// </summary>
        public AlgorithmIdentifier DigestAlgorithmID
        {
            get { return digestAlgorithm; }
        }

        /// <summary>
        /// Return the content digest that was calculated during verification.
        /// </summary>
        /// <returns>The content digest resulting from the last verify call.</returns>
        public byte[] GetContentDigest()
        {
            if (resultDigest == null)
            {
                throw new InvalidOperationException("method can only be called after verify.");
            }

            return (byte[])resultDigest.Clone();
        }

        /**
		* return a table of the signed attributes - indexed by
		* the OID of the attribute.
		*/
        public Asn1.Cms.AttributeTable SignedAttributes
        {
            get
            {
                if (signedAttributeSet != null && signedAttributeTable == null)
                {
                    signedAttributeTable = new Asn1.Cms.AttributeTable(signedAttributeSet);
                }
                return signedAttributeTable;
            }
        }

        /**
		* return a table of the unsigned attributes indexed by
		* the OID of the attribute.
		*/
        public Asn1.Cms.AttributeTable UnsignedAttributes
        {
            get
            {
                if (unsignedAttributeSet != null && unsignedAttributeTable == null)
                {
                    unsignedAttributeTable = new Asn1.Cms.AttributeTable(unsignedAttributeSet);
                }
                return unsignedAttributeTable;
            }
        }

        /**
		* return the encoded signature
		*/
        public byte[] GetSignature()
        {
            return (byte[])signature.Clone();
        }

        /**
		* Return a SignerInformationStore containing the counter signatures attached to this
		* signer. If no counter signatures are present an empty store is returned.
		*/
        public SignerInformationStore GetCounterSignatures()
        {
            // TODO There are several checks implied by the RFC3852 comments that are missing

            /*
			The countersignature attribute MUST be an unsigned attribute; it MUST
			NOT be a signed attribute, an authenticated attribute, an
			unauthenticated attribute, or an unprotected attribute.
			*/
            Asn1.Cms.AttributeTable unsignedAttributeTable = UnsignedAttributes;
            if (unsignedAttributeTable == null)
            {
                return new SignerInformationStore(new List<SignerInformation>(0));
            }

            IList<SignerInformation> counterSignatures = new List<SignerInformation>();

            /*
			The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
			UnsignedAttributes in a signerInfo may include multiple instances of
			the countersignature attribute.
			*/
            Asn1EncodableVector allCSAttrs = unsignedAttributeTable.GetAll(CmsAttributes.CounterSignature);

            foreach (Asn1.Cms.Attribute counterSignatureAttribute in allCSAttrs)
            {
                /*
				A countersignature attribute can have multiple attribute values.  The
				syntax is defined as a SET OF AttributeValue, and there MUST be one
				or more instances of AttributeValue present.
				*/
                Asn1Set values = counterSignatureAttribute.AttrValues;
                if (values.Count < 1)
                {
                    // TODO Throw an appropriate exception?
                }

                foreach (Asn1Encodable asn1Obj in values)
                {
                    /*
					Countersignature values have the same meaning as SignerInfo values
					for ordinary signatures, except that:

					   1. The signedAttributes field MUST NOT contain a content-type
					      attribute; there is no content type for countersignatures.

					   2. The signedAttributes field MUST contain a message-digest
					      attribute if it contains any other attributes.

					   3. The input to the message-digesting process is the contents
					      octets of the DER encoding of the signatureValue field of the
					      SignerInfo value with which the attribute is associated.
					*/
                    Asn1.Cms.SignerInfo si = Asn1.Cms.SignerInfo.GetInstance(asn1Obj.ToAsn1Object());

                    string digestName = CmsSignedHelper.Instance.GetDigestAlgName(si.DigestAlgorithm.Algorithm.Id);
                    // TODO:
                    //counterSignatures.Add(new SignerInformation(si, null, null, new CounterSignatureDigestCalculator(digestName, GetSignature())));
                }
            }

            return new SignerInformationStore(counterSignatures);
        }

        /**
		* return the DER encoding of the signed attributes.
		* @throws IOException if an encoding error occurs.
		*/
        public byte[] GetEncodedSignedAttributes()
        {
            return signedAttributeSet == null
                ? null
                : signedAttributeSet.GetEncoded(Asn1Encodable.Der);
        }

        private bool IsNull(
            Asn1Encodable o)
        {
            return (o is Asn1Null) || (o == null);
        }

        private bool doVerify(bool isRawVerifier, IVerifierFactory<AlgorithmIdentifier> verifierFactory, IDigestFactory<AlgorithmIdentifier> digestFactory)
        {
            IStreamCalculator<IVerifier> contentVerifier = verifierFactory.CreateCalculator();
            Stream sigOut = contentVerifier.Stream;

            try
            {
                if (resultDigest == null)
                {
                    IStreamCalculator<IBlockResult> calc = digestFactory.CreateCalculator();
                    if (content != null)
                    {
                        Stream digOut = calc.Stream;

                        if (signedAttributeSet == null)
                        {
                            if (isRawVerifier)
                            {
                                content.Write(digOut);
                            }
                            else
                            {
                                Stream cOut = new TeeOutputStream(digOut, sigOut);

                                content.Write(cOut);

                                cOut.Close();
                            }
                        }
                        else
                        {
                            content.Write(digOut);
                            byte[] enc = this.GetEncodedSignedAttributes();
                            sigOut.Write(enc, 0, enc.Length);
                        }

                        digOut.Close();
                    }
                    else if (signedAttributeSet != null)
                    {
                        byte[] enc = this.GetEncodedSignedAttributes();

                        sigOut.Write(enc, 0, enc.Length);
                    }
                    else
                    {
                        // TODO Get rid of this exception and just treat content==null as empty not missing?
                        throw new CmsException("data not encapsulated in signature - use detached constructor.");
                    }

                    resultDigest = calc.GetResult().Collect();
                }
                else
                {
                    if (signedAttributeSet == null)
                    {
                        if (content != null)
                        {
                            content.Write(sigOut);
                        }
                    }
                    else
                    {
                        byte[] enc = this.GetEncodedSignedAttributes();

                        sigOut.Write(enc, 0, enc.Length);
                    }
                }

                sigOut.Close();
            }
            catch (Exception e)
            {
                throw new CmsException("can't process object to create signature.", e);
            }

            // RFC 3852 11.1 Check the content-type attribute is correct
            {
                Asn1Object validContentType = GetSingleValuedSignedAttribute(
                    CmsAttributes.ContentType, "content-type");
                if (validContentType == null)
                {
                    if (!isCounterSignature && signedAttributeSet != null)
                    {
                        throw new CmsException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
                    }
                }
                else
                {
                    if (isCounterSignature)
                    {
                        throw new CmsException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");
                    }

                    if (!(validContentType is DerObjectIdentifier))
                    {
                        throw new CmsException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");
                    }

                    DerObjectIdentifier signedContentType = (DerObjectIdentifier)validContentType;

                    if (!signedContentType.Equals(contentType))
                    {
                        throw new CmsException("content-type attribute value does not match eContentType");
                    }
                }
            }

            Asn1.Cms.AttributeTable signedAttrTable = this.SignedAttributes;

            // RFC 6211 Validate Algorithm Identifier protection attribute if present
            {
                Asn1.Cms.AttributeTable unsignedAttrTable = this.UnsignedAttributes;
                if (unsignedAttrTable != null && unsignedAttrTable.GetAll(CmsAttributes.CmsAlgorithmProtect).Count > 0)
                {
                    throw new CmsException("A cmsAlgorithmProtect attribute MUST be a signed attribute");
                }
                if (signedAttrTable != null)
                {
                    Asn1EncodableVector protectionAttributes = signedAttrTable.GetAll(CmsAttributes.CmsAlgorithmProtect);
                    if (protectionAttributes.Count > 1)
                    {
                        throw new CmsException("Only one instance of a cmsAlgorithmProtect attribute can be present");
                    }
         
                    if (protectionAttributes.Count > 0)
                    {
                        Asn1.Cms.Attribute attr = Asn1.Cms.Attribute.GetInstance(protectionAttributes[0]);
                        if (attr.AttrValues.Count != 1)
                        {
                            throw new CmsException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
                        }

                        CmsAlgorithmProtection algorithmProtection = CmsAlgorithmProtection.GetInstance(attr.AttrValues[0]);

                        if (!CmsUtilities.IsEquivalent(algorithmProtection.DigestAlgorithm, info.DigestAlgorithm))
                        {
                            throw new CmsException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
                        }

                        if (!CmsUtilities.IsEquivalent(algorithmProtection.SignatureAlgorithm, info.DigestEncryptionAlgorithm))
                        {
                            throw new CmsException("CMS Algorithm Identifier Protection check failed for signatureAlgorithm");
                        }
                    }
                }
            }

            // RFC 3852 11.2 Check the message-digest attribute is correct
            {
                Asn1Encodable validMessageDigest = GetSingleValuedSignedAttribute(
                    CmsAttributes.MessageDigest, "message-digest");
                if (validMessageDigest == null)
                {
                    if (signedAttributeSet != null)
                    {
                        throw new CmsException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                    }
                }
                else
                {
                    if (!(validMessageDigest is Asn1OctetString))
                    {
                        throw new CmsException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                    }

                    Asn1OctetString signedMessageDigest = (Asn1OctetString)validMessageDigest;

                    if (!Arrays.ConstantTimeAreEqual(resultDigest, signedMessageDigest.GetOctets()))
                    {
                        throw new CmsSignerDigestMismatchException("message-digest attribute value does not match calculated value");
                    }
                }
            }

            // RFC 3852 11.4 Validate countersignature attribute(s)
            {
                if (signedAttrTable != null
                    && signedAttrTable.GetAll(CmsAttributes.CounterSignature).Count > 0)
                {
                    throw new CmsException("A countersignature attribute MUST NOT be a signed attribute");
                }

                Asn1.Cms.AttributeTable unsignedAttrTable = this.UnsignedAttributes;
                if (unsignedAttrTable != null)
                {
                    Asn1EncodableVector csAttrs = unsignedAttrTable.GetAll(CmsAttributes.CounterSignature);
                    for (int i = 0; i < csAttrs.Count; ++i)
                    {
                        Asn1.Cms.Attribute csAttr = Asn1.Cms.Attribute.GetInstance(csAttrs[i]);
                        if (csAttr.AttrValues.Count < 1)
                        {
                            throw new CmsException("A countersignature attribute MUST contain at least one AttributeValue");
                        }

                        // Note: We don't recursively validate the countersignature value
                    }
                }
            }

            try
            {
                if (signedAttributeSet == null && resultDigest != null)
                {
                    if (isRawVerifier)
                    {
                        if (SignatureAlgorithmID.Algorithm.Equals(PkcsObjectIdentifiers.RsaEncryption))
                        {
                            DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.Algorithm, DerNull.Instance), resultDigest);
                            byte[] data = digInfo.GetEncoded(Asn1Encodable.Der);

                            sigOut.Write(data, 0, data.Length);

                            sigOut.Close();

                            return contentVerifier.GetResult().IsVerified(this.GetSignature());
                        }

                        sigOut.Write(resultDigest, 0, resultDigest.Length);

                        sigOut.Close();

                        return contentVerifier.GetResult().IsVerified(this.GetSignature());
                    }
                }

                sigOut.Close();
         
                return contentVerifier.GetResult().IsVerified(this.GetSignature());
            }
            catch (IOException e)
            {
                throw new CmsException("can't process mime object to create signature.", e);
            }
        }

        /*
		* verify that the given public key successfully handles and confirms the
		* signature associated with this signer.
		*/
        public bool Verify(
            ISignerInformationVerifierProvider verifierProvider)
        {
            IVerifierFactory<AlgorithmIdentifier> verifierFact = verifierProvider.CreateVerifierFactory(this.SignatureAlgorithmID, this.DigestAlgorithmID);

            // Optional, but still need to validate if present
            Asn1.Cms.Time signingTime = GetSigningTime();

            if (signingTime != null)
            {
                IDatedVerifierFactory<AlgorithmIdentifier> datedFact = verifierFact as IDatedVerifierFactory<AlgorithmIdentifier>;
                if (datedFact != null)
                {
                    if (!datedFact.IsValidAt(signingTime.Date))
                    {
                        throw new CmsDatedVerifierNotValidException("verifier not valid at signingTime");
                    }
                }
            }

            return doVerify(verifierProvider.IsRawSigner, verifierFact, verifierProvider.CreateDigestFactory(this.DigestAlgorithmID));
        }

        /**
		* Return the base ASN.1 CMS structure that this object contains.
		*
		* @return an object containing a CMS SignerInfo structure.
		*/
        public Asn1.Cms.SignerInfo ToAsn1Structure()
        {
            return info;
        }

        private Asn1Object GetSingleValuedSignedAttribute(
            DerObjectIdentifier attrOID, string printableName)
        {

            Asn1.Cms.AttributeTable unsignedAttrTable = this.UnsignedAttributes;
            if (unsignedAttrTable != null
                && unsignedAttrTable.GetAll(attrOID).Count > 0)
            {
                throw new CmsException("The " + printableName
                    + " attribute MUST NOT be an unsigned attribute");
            }

            Asn1.Cms.AttributeTable signedAttrTable = this.SignedAttributes;
            if (signedAttrTable == null)
            {
                return null;
            }

            Asn1EncodableVector v = signedAttrTable.GetAll(attrOID);
            switch (v.Count)
            {
                case 0:
                    return null;
                case 1:
                    Asn1.Cms.Attribute t = (Asn1.Cms.Attribute)v[0];
                    Asn1Set attrValues = t.AttrValues;

                    if (attrValues.Count != 1)
                        throw new CmsException("A " + printableName
                            + " attribute MUST have a single attribute value");

                    return attrValues[0].ToAsn1Object();
                default:
                    throw new CmsException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
                        + printableName + " attribute");
            }
        }

        private Asn1.Cms.Time GetSigningTime()
        {
            Asn1Object validSigningTime = GetSingleValuedSignedAttribute(
                CmsAttributes.SigningTime, "signing-time");

            if (validSigningTime == null)
                return null;

            try
            {
                return Asn1.Cms.Time.GetInstance(validSigningTime);
            }
            catch (ArgumentException)
            {
                throw new CmsException("signing-time attribute value not a valid 'Time' structure");
            }
        }

        /**
		* Return a signer information object with the passed in unsigned
		* attributes replacing the ones that are current associated with
		* the object passed in.
		*
		* @param signerInformation the signerInfo to be used as the basis.
		* @param unsignedAttributes the unsigned attributes to add.
		* @return a copy of the original SignerInformationObject with the changed attributes.
		*/
        public static SignerInformation ReplaceUnsignedAttributes(
            SignerInformation signerInformation,
            Asn1.Cms.AttributeTable unsignedAttributes)
        {
            Asn1.Cms.SignerInfo sInfo = signerInformation.info;
            Asn1Set unsignedAttr = null;

            if (unsignedAttributes != null)
            {
                unsignedAttr = new DerSet(unsignedAttributes.ToAsn1EncodableVector());
            }

            return new SignerInformation(
                new Asn1.Cms.SignerInfo(
                    sInfo.SignerID,
                    sInfo.DigestAlgorithm,
                    sInfo.AuthenticatedAttributes,
                    sInfo.DigestEncryptionAlgorithm,
                    sInfo.EncryptedDigest,
                    unsignedAttr),
                signerInformation.contentType,
                signerInformation.content,
                null);
        }

        /**
		 * Return a signer information object with passed in SignerInformationStore representing counter
		 * signatures attached as an unsigned attribute.
		 *
		 * @param signerInformation the signerInfo to be used as the basis.
		 * @param counterSigners signer info objects carrying counter signature.
		 * @return a copy of the original SignerInformationObject with the changed attributes.
		 */
        public static SignerInformation AddCounterSigners(
            SignerInformation signerInformation,
            SignerInformationStore counterSigners)
        {
            // TODO Perform checks from RFC 3852 11.4

            Asn1.Cms.SignerInfo sInfo = signerInformation.info;
            Asn1.Cms.AttributeTable unsignedAttr = signerInformation.UnsignedAttributes;
            Asn1EncodableVector v;

            if (unsignedAttr != null)
            {
                v = unsignedAttr.ToAsn1EncodableVector();
            }
            else
            {
                v = new Asn1EncodableVector();
            }

            Asn1EncodableVector sigs = new Asn1EncodableVector();

            foreach (SignerInformation sigInf in counterSigners.GetAll())
            {
                sigs.Add(sigInf.ToAsn1Structure());
            }

            v.Add(new Asn1.Cms.Attribute(CmsAttributes.CounterSignature, new DerSet(sigs)));

            return new SignerInformation(
                new Asn1.Cms.SignerInfo(
                    sInfo.SignerID,
                    sInfo.DigestAlgorithm,
                    sInfo.AuthenticatedAttributes,
                    sInfo.DigestEncryptionAlgorithm,
                    sInfo.EncryptedDigest,
                    new DerSet(v)),
                signerInformation.contentType,
                signerInformation.content,
                null);
        }
    }
}
