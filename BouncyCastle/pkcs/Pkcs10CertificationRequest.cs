using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;
using System.IO;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// Holding class for a PKCS#10 certification request.
    /// </summary>
    public class Pkcs10CertificationRequest
    {
        private static AttributePkcs[] EMPTY_ARRAY = new AttributePkcs[0];

        private CertificationRequest certificationRequest;

        private static CertificationRequest parseBytes(byte[] encoding)
        {
            try
            {
                return CertificationRequest.GetInstance(Asn1Object.FromByteArray(encoding));
            }
            catch (ArgumentException e)
            {
                throw new PkcsIOException("malformed data: " + e.Message, e);
            }
            catch (Exception e)
            {
                throw new PkcsIOException("malformed data: " + e.Message, e);
            }
        }

        /// <summary>
        /// Create a Pkcs10CertificationRequestHolder from an underlying ASN.1 structure.
        /// </summary>
        /// <param name="certificationRequest">The underlying ASN.1 structure representing a request.</param>
        public Pkcs10CertificationRequest(CertificationRequest certificationRequest)
        {
            this.certificationRequest = certificationRequest;
        }

        /// <summary>
        /// Create a Pkcs10CertificationRequestHolder from the passed in bytes.
        /// </summary>
        /// <param name="encoded">BER/DER encoding of the CertificationRequest structure.</param>
        public Pkcs10CertificationRequest(byte[] encoded) : this(parseBytes(encoded))
        {

        }

        /// <summary>
        /// Return the underlying ASN.1 structure for this request.
        /// </summary>
        /// <returns>A CertificateRequest object.</returns>
        public CertificationRequest ToAsn1Structure()
        {
            return certificationRequest;
        }

        /// <summary>
        /// Return the subject on this request.
        /// </summary>
        public X500Name Subject
        {
            get
            {
                return X500Name.GetInstance(certificationRequest.GetCertificationRequestInfo().Subject);
            }
        }

        /// <summary>
        /// Return the details of the signature algorithm used to create this request.
        /// </summary>
        public AlgorithmIdentifier SignatureAlgorithm
        {
            get
            {
                return certificationRequest.SignatureAlgorithm;
            }
        }

        /// <summary>
        /// Return the bytes making up the signature associated with this request.
        /// </summary>
        /// <returns>The request signature bytes.</returns>
        public byte[] GetSignature()
        {
            return certificationRequest.Signature.GetOctets();
        }

        /// <summary>
        /// Return the SubjectPublicKeyInfo describing the public key this request is carrying.
        /// </summary>
        public SubjectPublicKeyInfo SubjectPublicKeyInfo
        {
            get
            {
                return certificationRequest.GetCertificationRequestInfo().SubjectPublicKeyInfo;
            }
        }

        /// <summary>
        /// Return the attributes, if any associated with this request.
        /// </summary>
        /// <returns>An array of Attribute, zero length if none present.</returns>
        public AttributePkcs[] GetAttributes()
        {
            Asn1Set attrSet = certificationRequest.GetCertificationRequestInfo().Attributes;

            if (attrSet == null)
            {
                return EMPTY_ARRAY;
            }

            AttributePkcs[] attrs = new AttributePkcs[attrSet.Count];

            for (int i = 0; i != attrSet.Count; i++)
            {
                attrs[i] = AttributePkcs.GetInstance(attrSet[i]);
            }

            return attrs;
        }

        /// <summary>
        /// Return an  array of attributes matching the passed in type OID.
        /// </summary>
        /// <param name="type">The type of the attribute being looked for.</param>
        /// <returns>An array of Attribute of the requested type, zero length if none present.</returns>
        public AttributePkcs[] GetAttributes(DerObjectIdentifier type)
        {
            Asn1Set attrSet = certificationRequest.GetCertificationRequestInfo().Attributes;

            if (attrSet == null)
            {
                return EMPTY_ARRAY;
            }

            IList list = Platform.CreateArrayList();

            for (int i = 0; i != attrSet.Count; i++)
            {
                AttributePkcs attr = AttributePkcs.GetInstance(attrSet[i]);
                if (attr.AttrType.Equals(type))
                {
                    list.Add(attr);
                }
            }

            if (list.Count == 0)
            {
                return EMPTY_ARRAY;
            }

            AttributePkcs[] attrs = new AttributePkcs[list.Count];

            for (int i = 0; i != attrs.Length; i++)
            {
                attrs[i] = (AttributePkcs)list[i];
            }
            return attrs;
        }

        public byte[] GetEncoded()
        {
            return certificationRequest.GetEncoded();
        }

        /// <summary>
        /// Validate the signature on the Pkcs10 certification request in this holder.
        /// </summary>
        /// <param name="verifierProvider">A ContentVerifierProvider that can generate a verifier for the signature.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        public bool IsSignatureValid(IVerifierFactoryProvider<AlgorithmIdentifier> verifierProvider)
        {
            CertificationRequestInfo requestInfo = certificationRequest.GetCertificationRequestInfo();

            IStreamCalculator<IVerifier> calculator;

            try
            {
                IVerifierFactory<AlgorithmIdentifier> verifier = verifierProvider.CreateVerifierFactory(certificationRequest.SignatureAlgorithm);

                calculator = verifier.CreateCalculator();

                Stream sOut = calculator.Stream;

                byte[] data = requestInfo.GetEncoded(Asn1Encodable.Der);

                sOut.Write(data, 0, data.Length);

                sOut.Close();

                return calculator.GetResult().IsVerified(this.GetSignature());
            }
            catch (Exception e)
            {
                throw new PkcsException("unable to process signature: " + e.Message, e);
            }
        }

        public override bool Equals(Object o)
        {
            if (o == this)
            {
                return true;
            }

            if (!(o is Pkcs10CertificationRequest))
            {
                return false;
            }

            Pkcs10CertificationRequest other = (Pkcs10CertificationRequest)o;

            return this.ToAsn1Structure().Equals(other.ToAsn1Structure());
        }

        public override int GetHashCode()
        {
            return this.ToAsn1Structure().GetHashCode();
        }
    }
}
