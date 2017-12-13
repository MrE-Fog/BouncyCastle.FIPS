using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Cert.Selector
{
    public class X509CertificateSelector : ISelector<X509Certificate>, ISelector<byte[]>
    {
        private byte[] subjectKeyId;

        private X500Name issuer;
        private BigInteger serialNumber;

        /**
         * Construct a selector with the value of a public key's subjectKeyId.
         *
         * @param subjectKeyId a subjectKeyId
         */
        public X509CertificateSelector(byte[] subjectKeyId) : this(null, null, subjectKeyId)
        {

        }

        /**
         * Construct a signer ID based on the issuer and serial number of the signer's associated
         * certificate.
         *
         * @param issuer the issuer of the signer's associated certificate.
         * @param serialNumber the serial number of the signer's associated certificate.
         */
        public X509CertificateSelector(X500Name issuer, BigInteger serialNumber) : this(issuer, serialNumber, null)
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
        public X509CertificateSelector(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
        {
            this.issuer = issuer;
            this.serialNumber = serialNumber;
            this.subjectKeyId = subjectKeyId;
        }

        public X500Name Issuer
        {
            get
            {
                return issuer;
            }
        }

        public BigInteger SerialNumber
        {
            get
            {
                return serialNumber;
            }
        }

        public byte[] GetSubjectKeyIdentifier()
        {
            return Arrays.Clone(subjectKeyId);
        }

        public override int GetHashCode()
        {
            int code = Arrays.GetHashCode(subjectKeyId);

            if (this.serialNumber != null)
            {
                code ^= this.serialNumber.GetHashCode();
            }

            if (this.issuer != null)
            {
                code ^= this.issuer.GetHashCode();
            }

            return code;
        }

        public override bool Equals(
            Object o)
        {
            if (!(o is X509CertificateSelector))
            {
                return false;
            }

            X509CertificateSelector id = (X509CertificateSelector)o;

            return Arrays.AreEqual(subjectKeyId, id.subjectKeyId)
                && equalsObj(this.serialNumber, id.serialNumber)
                && equalsObj(this.issuer, id.issuer);
        }

        private bool equalsObj(Object a, Object b)
        {
            return (a != null) ? a.Equals(b) : b == null;
        }

        public bool Match(X509Certificate cert)
        {
            if (this.SerialNumber != null)
            {
                IssuerAndSerialNumber iAndS = new IssuerAndSerialNumber(cert.ToAsn1Structure());

                return iAndS.Name.Equals(this.issuer)
                    && iAndS.SerialNumber.Value.Equals(this.serialNumber);
            }
            else if (subjectKeyId != null)
            {
                byte[] ext = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);

                if (ext == null)
                {
                    return Arrays.AreEqual(subjectKeyId, MSOutlookKeyIdCalculator.CalculateKeyId(cert.SubjectPublicKeyInfo));
                }

                byte[] subKeyID = Asn1OctetString.GetInstance(ext).GetOctets();

                return Arrays.AreEqual(subjectKeyId, subKeyID);
            }

            return false;
        }

        public bool Match(byte[] subjectKey)
        {
            return Arrays.AreEqual(subjectKeyId, subjectKey);
        }
    }
}
