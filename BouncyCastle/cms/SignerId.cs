using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Cert.Selector;
using Org.BouncyCastle.Cert;

namespace Org.BouncyCastle.Cms
{
    /**
    * a basic index for a signer.
    */
    public class SignerID: ISelector<SignerInformation>, ISelector<X509Certificate>
    {
        private X509CertificateSelector baseSelector;

        private SignerID(X509CertificateSelector baseSelector)
        {
            this.baseSelector = baseSelector;
        }

        /**
         * Construct a signer ID with the value of a public key's subjectKeyId.
         *
         * @param subjectKeyId a subjectKeyId
         */
        public SignerID(byte[] subjectKeyId): this(null, null, subjectKeyId)
        {
            
        }

        /**
         * Construct a signer ID based on the issuer and serial number of the signer's associated
         * certificate.
         *
         * @param issuer the issuer of the signer's associated certificate.
         * @param serialNumber the serial number of the signer's associated certificate.
         */
        public SignerID(X500Name issuer, BigInteger serialNumber): this(issuer, serialNumber, null)
        {
            
        }

        /**
         * Construct a signer ID based on the issuer and serial number of the signer's associated
         * certificate.
         *
         * @param issuer the issuer of the signer's associated certificate.
         * @param serialNumber the serial number of the signer's associated certificate.
         * @param subjectKeyId the subject key identifier to use to match the signers associated certificate.
         */
        public SignerID(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId): this(new X509CertificateSelector(issuer, serialNumber, subjectKeyId))
        {
            
        }

        public X500Name Issuer
        {
            get
            {
                return baseSelector.Issuer;
            }
        }

        public BigInteger SerialNumber
        {
            get
            {
                return baseSelector.SerialNumber;
            }
        }

        public byte[] GetSubjectKeyIdentifier()
        {
            return baseSelector.GetSubjectKeyIdentifier();
        }

        public override int GetHashCode()
        {
            return baseSelector.GetHashCode();
        }

        public override bool Equals(
            Object o)
        {
            if (!(o is SignerID))
        {
                return false;
            }

            SignerID id = (SignerID)o;

            return this.baseSelector.Equals(id.baseSelector);
        }

        public bool Match(SignerInformation signerInfo)
        {
            return signerInfo.SignerID.Equals(this);
        }

        public bool Match(X509Certificate cert)
        {
            return baseSelector.Match(cert);
        }
    }
}
