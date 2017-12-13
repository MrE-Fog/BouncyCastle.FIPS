using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Operators.Utilities;
using System.IO;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    internal interface ISignerInfoGenerator
    {
        SignerInfo Generate(DerObjectIdentifier contentType, AlgorithmIdentifier digestAlgorithm,
            byte[] calculatedDigest);
    }

    public class SignerInfoGenerator
    {
        internal IDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        internal ISignatureFactory<AlgorithmIdentifier> signer;
        internal IStreamCalculator<IBlockResult> signerCalculator;
        internal IDigestFactory<AlgorithmIdentifier> digester;
        internal IStreamCalculator<IBlockResult> digestCalculator;
        internal SignerIdentifier sigId;
        internal ICmsAttributeTableGenerator signedGen;
        internal ICmsAttributeTableGenerator unsignedGen;

        private ISignatureEncryptionAlgorithmFinder sigEncAlgFinder;

        private bool isDirectSignature;
        private X509Certificate certificate;
        private byte[] calculatedDigest;

        internal SignerInfoGenerator(SignerIdentifier sigId, ISignatureFactory<AlgorithmIdentifier> signerFactory, IDigestFactoryProvider<AlgorithmIdentifier> digesterProvider, ISignatureEncryptionAlgorithmFinder sigEncAlgFinder) : this(sigId, signerFactory, digesterProvider, sigEncAlgFinder, false)
        {

        }

        internal SignerInfoGenerator(SignerIdentifier sigId, ISignatureFactory<AlgorithmIdentifier> signerFactory, IDigestFactoryProvider<AlgorithmIdentifier> digesterProvider, ISignatureEncryptionAlgorithmFinder sigEncAlgFinder, bool isDirectSignature)
        {
            this.sigId = sigId;
            this.signer = signerFactory;
            this.signerCalculator = signerFactory.CreateCalculator();

            if (digesterProvider != null)
            {
                this.digester = digesterProvider.CreateDigestFactory(digAlgFinder.Find(signer.AlgorithmDetails));
                this.digestCalculator = digester.CreateCalculator();
            }
            else
            {
                this.digester = null;
            }

            this.sigEncAlgFinder = sigEncAlgFinder;

            this.isDirectSignature = isDirectSignature;
            if (this.isDirectSignature)
            {
                this.signedGen = null;
                this.unsignedGen = null;
            }
            else
            {
                this.signedGen = new DefaultSignedAttributeTableGenerator();
                this.unsignedGen = null;
            }
        }

        internal SignerInfoGenerator(SignerIdentifier sigId, ISignatureFactory<AlgorithmIdentifier> contentSigner, IDigestFactoryProvider<AlgorithmIdentifier> digesterProvider, ISignatureEncryptionAlgorithmFinder sigEncAlgFinder, ICmsAttributeTableGenerator signedGen, ICmsAttributeTableGenerator unsignedGen)
        {
            this.sigId = sigId;
            this.signer = contentSigner;
            this.signerCalculator = contentSigner.CreateCalculator();
            if (digesterProvider != null)
            {
                this.digester = digesterProvider.CreateDigestFactory(digAlgFinder.Find(signer.AlgorithmDetails));
                this.digestCalculator = digester.CreateCalculator();
            }
            else
            {
                this.digester = null;
            }
            this.sigEncAlgFinder = sigEncAlgFinder;
            this.signedGen = signedGen;
            this.unsignedGen = unsignedGen;
            this.isDirectSignature = false;
        }

        internal void setAssociatedCertificate(X509Certificate certificate)
        {
            this.certificate = certificate;
        }

        public SignerIdentifier SID
        {
            get
            {
                return sigId;
            }
        }

        public int GeneratedVersion
        {
            get
            {
                return sigId.IsTagged ? 3 : 1;
            }
        }

        public bool HasAssociatedCertificate
        {
            get
            {
                return certificate != null;
            }
        }

        public X509Certificate AssociatedCertificate
        {
            get
            {
                return certificate;
            }
        }

        public AlgorithmIdentifier GetDigestAlgorithm()
        {
            if (digester != null)
            {
                return digester.AlgorithmDetails;
            }

            return digAlgFinder.Find(signer.AlgorithmDetails);
        }

        public Stream GetCalculatingOutputStream()
        {
            if (digester != null)
            {
                if (signedGen == null)
                {
                    return new TeeOutputStream(digestCalculator.Stream, signerCalculator.Stream);
                }
                return digestCalculator.Stream;
            }
            else
            {
                return signerCalculator.Stream;
            }
        }

        public byte[] getCalculatedDigest()
        {
            if (calculatedDigest != null)
            {
                return Arrays.Clone(calculatedDigest);
            }

            return null;
        }

        public ICmsAttributeTableGenerator SignedAttributeTableGenerator
        {
            get
            {
                return signedGen;
            }
        }

        public ICmsAttributeTableGenerator UnsignedAttributeTableGenerator
        {
            get
            {
                return unsignedGen;
            }
        }

        public SignerInfo Generate(DerObjectIdentifier contentType)
        {
            try
            {
                /* RFC 3852 5.4
                 * The result of the message digest calculation process depends on
                 * whether the signedAttrs field is present.  When the field is absent,
                 * the result is just the message digest of the content as described
                 *
                 * above.  When the field is present, however, the result is the message
                 * digest of the complete DER encoding of the SignedAttrs value
                 * contained in the signedAttrs field.
                 */
                Asn1Set signedAttr = null;

                AlgorithmIdentifier digestEncryptionAlgorithm = sigEncAlgFinder.FindEncryptionAlgorithm(signer.AlgorithmDetails);

                AlgorithmIdentifier digestAlg = null;

                if (signedGen != null)
                {
                    digestAlg = digester.AlgorithmDetails;

                    digestCalculator.Stream.Close();
                    calculatedDigest = digestCalculator.GetResult().Collect();

                    IDictionary<string, object> parameters = getBaseParameters(contentType, digester.AlgorithmDetails, digestEncryptionAlgorithm, calculatedDigest);
                    Asn1.Cms.AttributeTable signed = signedGen.GetAttributes(parameters);

                    signedAttr = getAttributeSet(signed);

                    // sig must be composed from the DER encoding.
                    Stream sOut = signerCalculator.Stream;
                    byte[] data = signedAttr.GetEncoded(Asn1Encodable.Der);

                    sOut.Write(data, 0, data.Length);
                }
                else
                {
                    if (digester != null)
                    {
                        digestAlg = digester.AlgorithmDetails;

                        digestCalculator.Stream.Close();
                        calculatedDigest = digestCalculator.GetResult().Collect();
                    }
                    else
                    {
                        digestAlg = digAlgFinder.Find(signer.AlgorithmDetails);
                        calculatedDigest = null;
                    }
                }

                signerCalculator.Stream.Close();

                byte[] sigBytes = signerCalculator.GetResult().Collect();

                Asn1Set unsignedAttr = null;
                if (unsignedGen != null)
                {
                    IDictionary<string,object> parameters = getBaseParameters(contentType, digestAlg, digestEncryptionAlgorithm, calculatedDigest);
                    parameters.Add(CmsAttributeTableParameter.Signature, Arrays.Clone(sigBytes));

                    Asn1.Cms.AttributeTable unsigned = unsignedGen.GetAttributes(parameters);

                    unsignedAttr = getAttributeSet(unsigned);
                }

                return new SignerInfo(sigId, digestAlg,
                    signedAttr, digestEncryptionAlgorithm, new DerOctetString(sigBytes), unsignedAttr);
            }
            catch (IOException e)
            {
                throw new CmsException("encoding error.", e);
            }
        }

        private IDictionary<string,object> getBaseParameters(DerObjectIdentifier contentType, AlgorithmIdentifier digAlgId, AlgorithmIdentifier sigAlgId, byte[] hash)
        {
            IDictionary<string, object> param = new Dictionary<string,object>();

            if (contentType != null)
            {
                param.Add(CmsAttributeTableParameter.ContentType, contentType);
            }

            param.Add(CmsAttributeTableParameter.DigestAlgorithmIdentifier, digAlgId);
            param.Add(CmsAttributeTableParameter.SignatureAlgorithmIdentifier, sigAlgId);
            param.Add(CmsAttributeTableParameter.Digest, Arrays.Clone(hash));

            return param;
        }

        private Asn1Set getAttributeSet(
            Asn1.Cms.AttributeTable attr)
        {
            if (attr != null)
            {
                return new DerSet(attr.ToAsn1EncodableVector());
            }

            return null;
        }
    }
}
