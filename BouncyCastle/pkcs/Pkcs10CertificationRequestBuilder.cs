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
    /// A class for creating PKCS#10 Certification requests.
    /// </summary>
    /// <remarks>
    /// <code>
    /// CertificationRequest ::= SEQUENCE {
    ///     certificationRequestInfo  CertificationRequestInfo,
    ///     signatureAlgorithm        AlgorithmIdentifier{ { SignatureAlgorithms } },
    ///     signature                 BIT STRING
    /// }
    ///
    /// CertificationRequestInfo ::= SEQUENCE {
    ///     version             INTEGER { v1(0) }
    ///     subject             Name,
    ///     subjectPKInfo   SubjectPublicKeyInfo{ { PKInfoAlgorithms } },
    ///     attributes[0] Attributes{ { CRIAttributes } }
    ///  }
    ///
    /// Attributes
    ///     { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
    ///
    /// Attribute
    ///     { ATTRIBUTE:IOSet } ::= SEQUENCE {
    ///      type    ATTRIBUTE.&amp;id({ IOSet}),
    ///      values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({ IOSet}{\@type})
    ///     }
    /// </code>
    /// </remarks>
    public class Pkcs10CertificationRequestBuilder
    {
        private SubjectPublicKeyInfo publicKeyInfo;
        private X500Name subject;
        private IList attributes = Platform.CreateArrayList();
        private bool leaveOffEmpty = false;

        /// <summary>
        /// Constructor using an encoded subject public key info.
        /// </summary>
        /// <param name="subject">The subject for the certification request.</param>
        /// <param name="encodedPublicKeyInfo">An encoding of the public key to go in the final certificate.</param>
        public Pkcs10CertificationRequestBuilder(X500Name subject, byte[] encodedPublicKeyInfo): this(subject, SubjectPublicKeyInfo.GetInstance(encodedPublicKeyInfo))
        {
        }

        /// <summary>
        /// Constructor using a subject public key info.
        /// </summary>
        /// <param name="subject">The subject for the certification request.</param>
        /// <param name="publicKeyInfo">The public key to go in the final certificate and be associated with the subject.</param>
        public Pkcs10CertificationRequestBuilder(X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
        {
            this.subject = subject;
            this.publicKeyInfo = publicKeyInfo;
        }

        /// <summary>
        /// Add an attribute to the certification request we are building.
        /// </summary>
        /// <param name="attrType">the OID giving the type of the attribute.</param>
        /// <param name="attrValue">the ASN.1 structure that forms the value of the attribute.</param>
        /// <returns>The current builder instance.</returns>
        public Pkcs10CertificationRequestBuilder AddAttribute(DerObjectIdentifier attrType, Asn1Encodable attrValue)
        {
            attributes.Add(new AttributePkcs(attrType, new DerSet(attrValue)));

            return this;
        }

        /// <summary>
        /// Add an attribute with multiple values to the certification request we are building.
        /// </summary>
        /// <param name="attrType">the OID giving the type of the attribute.</param>
        /// <param name="attrValues">an array of ASN.1 structures that form the value of the attribute.</param>
        /// <returns>The current builder instance.</returns>
        public Pkcs10CertificationRequestBuilder AddAttribute(DerObjectIdentifier attrType, Asn1Encodable[] attrValues)
        {
            attributes.Add(new AttributePkcs(attrType, new DerSet(attrValues)));

            return this;
        }

        /// <summary>
        /// The attributes field in Pkcs10 should encoded to an empty tagged set if there are
        /// no attributes. Some CAs will reject requests with the attribute field present.
        /// </summary>
        /// <param name="leaveOffEmpty">true if empty attributes should be left out of the encoding false otherwise.</param>
        /// <returns>The current builder instance.</returns>
        public Pkcs10CertificationRequestBuilder SetLeaveOffEmptyAttributes(bool leaveOffEmpty)
        {
            this.leaveOffEmpty = leaveOffEmpty;

            return this;
        }

        /// <summary>
        /// Generate an PKCS#10 request based on the past in signer.
        /// </summary>
        /// <param name="signerFactory">the content signer to be used to generate the signature validating the certificate.</param>
        /// <returns>a holder containing the resulting PKCS#10 certification request.</returns>
        public Pkcs10CertificationRequest Build(
            ISignatureFactory<AlgorithmIdentifier> signerFactory)
        {
            CertificationRequestInfo info;

            if (attributes.Count == 0)
            {
                if (leaveOffEmpty)
                {
                    info = new CertificationRequestInfo(subject, publicKeyInfo, null);
                }
                else
                {
                    info = new CertificationRequestInfo(subject, publicKeyInfo, new DerSet());
                }
            }
            else
            {
                Asn1EncodableVector v = new Asn1EncodableVector();

                for (int i = 0; i != attributes.Count; i++)
                {
                    v.Add(AttributePkcs.GetInstance(attributes[i]));
                }

                info = new CertificationRequestInfo(subject, publicKeyInfo, new DerSet(v));
            }

            try
            {
                IStreamCalculator<IBlockResult> signer = signerFactory.CreateCalculator();

                Stream sOut = signer.Stream;

                byte[] data = info.GetEncoded(Asn1Encodable.Der);

                sOut.Write(data, 0, data.Length);

                sOut.Close();

                return new Pkcs10CertificationRequest(new CertificationRequest(info, signerFactory.AlgorithmDetails, new DerBitString(signer.GetResult().Collect())));
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("cannot produce certification request signature: " + e.Message, e);
            }
        }
    }
}
