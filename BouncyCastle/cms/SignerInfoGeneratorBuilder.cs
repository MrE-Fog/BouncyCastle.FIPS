using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Cms
{
    public class SignerInfoGeneratorBuilder
    {
        private bool directSignature;
        private ICmsAttributeTableGenerator signedGen;
        private ICmsAttributeTableGenerator unsignedGen;

        private IDigestFactoryProvider<AlgorithmIdentifier> digestProvider;
        private ISignatureEncryptionAlgorithmFinder sigEncAlgFinder;

        /**
         *  Base constructor.
         *
         * @param digestProvider  a provider of digest calculators for the algorithms required in the signature and attribute calculations.
         */
        public SignerInfoGeneratorBuilder(IDigestFactoryProvider<AlgorithmIdentifier> digestProvider) : this(digestProvider, new DefaultSignatureEncryptionAlgorithmFinder())
        {
        }

        /**
     *  Base constructor.
     *
     * @param digestProvider  a provider of digest calculators for the algorithms required in the signature and attribute calculations.
     */
        public SignerInfoGeneratorBuilder(IDigestFactoryProvider<AlgorithmIdentifier> digestProvider, ISignatureEncryptionAlgorithmFinder sigEncAlgFinder)
        {
            this.digestProvider = digestProvider;
            this.sigEncAlgFinder = sigEncAlgFinder;
        }

        /**
         * If the passed in flag is true, the signer signature will be based on the data, not
         * a collection of signed attributes, and no signed attributes will be included.
         *
         * @return the builder object
         */
        public SignerInfoGeneratorBuilder SetDirectSignature(bool hasNoSignedAttributes)
        {
            this.directSignature = hasNoSignedAttributes;

            return this;
        }

        /**
         *  Provide a custom signed attribute generator.
         *
         * @param signedGen a generator of signed attributes.
         * @return the builder object
         */
        public SignerInfoGeneratorBuilder WithSignedAttributeGenerator(ICmsAttributeTableGenerator signedGen)
        {
            this.signedGen = signedGen;

            return this;
        }

        /**
         * Provide a generator of unsigned attributes.
         *
         * @param unsignedGen  a generator for signed attributes.
         * @return the builder object
         */
        public SignerInfoGeneratorBuilder WithUnsignedAttributeGenerator(ICmsAttributeTableGenerator unsignedGen)
        {
            this.unsignedGen = unsignedGen;

            return this;
        }

        /// <summary>
        /// Build a generator with the passed in certificate issuer and serial number as the signerIdentifier.
        /// </summary>
        /// <param name="contentSigner">operator for generating the final signature in the SignerInfo with.</param>
        /// <param name="certificate">carrier for the X.509 certificate related to the contentSigner.</param>
        /// <returns>a SignerInfoGenerator</returns>
        public SignerInfoGenerator Build(ISignatureFactory<AlgorithmIdentifier> contentSigner, X509Certificate certificate)
        {
            SignerIdentifier sigId = new SignerIdentifier(new IssuerAndSerialNumber(certificate.IssuerDN, new DerInteger(certificate.SerialNumber)));

            SignerInfoGenerator sigInfoGen = CreateGenerator(contentSigner, sigId);

            sigInfoGen.setAssociatedCertificate(certificate);

            return sigInfoGen;
        }

        /// <summary>
        /// Build a generator with the passed in subjectKeyIdentifier as the signerIdentifier. If used  you should
        /// try to follow the calculation described in RFC 5280 section 4.2.1.2.
        /// </summary>
        /// <param name="contentSigner">operator factory for generating the final signature in the SignerInfo with.</param>
        /// <param name="subjectKeyIdentifier">key identifier to identify the public key for verifying the signature.</param>
        /// <returns>a SignerInfoGenerator</returns>
        public SignerInfoGenerator Build(ISignatureFactory<AlgorithmIdentifier> contentSigner, byte[] subjectKeyIdentifier)
        {
            SignerIdentifier sigId = new SignerIdentifier(new DerOctetString(subjectKeyIdentifier));

            return CreateGenerator(contentSigner, sigId);
        }

        private SignerInfoGenerator CreateGenerator(ISignatureFactory<AlgorithmIdentifier> contentSigner, SignerIdentifier sigId)
        {
            if (directSignature)
            {
                return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder, true);
            }

            if (signedGen != null || unsignedGen != null)
            {
                if (signedGen == null)
                {
                    signedGen = new DefaultSignedAttributeTableGenerator();
                }

                return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder, signedGen, unsignedGen);
            }

            return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder);
        }
    }
}
