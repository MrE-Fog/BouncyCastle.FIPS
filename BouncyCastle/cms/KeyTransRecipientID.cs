using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Cert.Selector;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Cms
{
    public class KeyTransRecipientID: IRecipientID<RecipientInformation>, ISelector<X509Certificate>
    {
        private X509CertificateSelector baseSelector;

        private KeyTransRecipientID(X509CertificateSelector baseSelector)
        {
            this.baseSelector = baseSelector;
        }

        public RecipientType Type
        {
            get
            {
                return RecipientType.KeyTrans;
            }
        }

        /// <summary>
        /// Construct a key trans recipient ID with the value of a public key's subjectKeyId.
        /// </summary>
        /// <param name="subjectKeyId">a subjectKeyId</param>
        public KeyTransRecipientID(byte[] subjectKeyId): this(null, null, subjectKeyId)
        {
            
        }

        /// <summary>
        /// Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated certificate.
        /// </summary>
        /// <param name="issuer">The issuer of the recipient's associated certificate.</param>
        /// <param name="serialNumber">The serial number of the recipient's associated certificate.</param>
        public KeyTransRecipientID(X500Name issuer, BigInteger serialNumber): this(issuer, serialNumber, null)
        {
        
        }

        /// <summary>
        /// Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated certificate.
        /// </summary>
        /// <param name="certificate">The recipient's associated certificate.</param>
        public KeyTransRecipientID(X509Certificate certificate) : this(certificate.IssuerDN, certificate.SerialNumber, GetSubjectKeyID(certificate))
        {

        }

        /// <summary>
        /// Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated certificate.
        /// </summary>
        /// <param name="issuer">The issuer of the recipient's associated certificate.</param>
        /// <param name="serialNumber">The serial number of the recipient's associated certificate.</param>
        /// <param name="subjectKeyId">The subject key identifier to use to match the recipients associated certificate.</param>
        public KeyTransRecipientID(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId): this(new X509CertificateSelector(issuer, serialNumber, subjectKeyId))
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
            if (!(o is KeyTransRecipientID))
            { 
                return false;
            }

            KeyTransRecipientID id = (KeyTransRecipientID)o;

            return this.baseSelector.Equals(id.baseSelector);
        }

        public bool Match(RecipientInformation obj)
        {
            return obj.RecipientID.Equals(this);    
        }

        public bool Match(X509Certificate obj)
        {
            return baseSelector.Match(obj);
        }

        private static byte[] GetSubjectKeyID(X509Certificate cert)
        {
            byte[] ext = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);

            if (ext != null)
            {
                return Asn1OctetString.GetInstance(ext).GetOctets();
            }

            return null;
        }
    }
}
