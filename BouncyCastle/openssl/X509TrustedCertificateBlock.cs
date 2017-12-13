using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>
    /// Holder for an OpenSSL trusted certificate block.
    /// </summary>
    public class X509TrustedCertificateBlock
    {
        private readonly X509Certificate certificate;
        private readonly CertificateTrustBlock trustBlock;

        /// <summary>
        /// Base constructor - from a certificate and a trust block.
        /// </summary>
        /// <param name="certificate">The certificate to contain.</param>
        /// <param name="trustBlock">The trust block to associate with the certififace.</param>
        public X509TrustedCertificateBlock(X509Certificate certificate, CertificateTrustBlock trustBlock)
        {
            this.certificate = certificate;
            this.trustBlock = trustBlock;
        }

        /// <summary>
        /// Base constructor - from a byte encoding.
        /// </summary>
        /// <param name="encoding">A byte encoding of a trusted certificate block.</param>
        public X509TrustedCertificateBlock(byte[] encoding)
        {
            Asn1InputStream aIn = new Asn1InputStream(encoding);

            this.certificate = new X509Certificate(aIn.ReadObject().GetEncoded());
            this.trustBlock = new CertificateTrustBlock(aIn.ReadObject().GetEncoded());
        }

        /// <summary>
        /// Return a binary encoding of the trusted certificate block.
        /// </summary>
        /// <returns>A byte array containing the encoded object.</returns>
        public byte[] GetEncoded()
        {
            return Arrays.Concatenate(certificate.GetEncoded(), trustBlock.ToAsn1Sequence().GetEncoded());
        }

        /// <summary>
        /// Return the certificate associated with this Trusted Certificate
        /// </summary>
        /// <returns>The certificate.</returns>
        public X509Certificate Certificate
        {
            get
            {
                return certificate;
            }
        }

        /// <summary>
        /// Return the trust block associated with this Trusted Certificate
        /// </summary>
        /// <returns>The trust block.</returns>
        public CertificateTrustBlock TrustBlock
        {
            get
            {
                return trustBlock;
            }
        }
    }
}
