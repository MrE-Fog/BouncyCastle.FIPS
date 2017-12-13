using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cert
{
    /// <summary>
    /// Generator for an X.509 Version 2 CRL.
    /// </summary>
    public class X509V2CrlGenerator
	{
		private readonly X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

		private V2TbsCertListGenerator	tbsGen;

        /// <summary>
        /// Base constructor.
        /// </summary>
		public X509V2CrlGenerator()
		{
			tbsGen = new V2TbsCertListGenerator();
		}

        /// <summary>
        /// Reset the generator.
        /// </summary>
        public void Reset()
		{
			tbsGen = new V2TbsCertListGenerator();
			extGenerator.Reset();
        }

        /// <summary>
        /// Set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
		/// certificate.
        /// </summary>
        /// <param name="issuer">The issuer name.</param>
        public void SetIssuerDN(
			X500Name issuer)
		{
			tbsGen.SetIssuer(issuer);
		}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="date"></param>
		public void SetThisUpdate(
			DateTime date)
		{
			tbsGen.SetThisUpdate(new Time(date));
		}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="date"></param>
		public void SetNextUpdate(
			DateTime date)
		{
			tbsGen.SetNextUpdate(new Time(date));
		}

        /// <summary>
        /// Add a CRL entry with a CrlReason extension.
        /// Reason being as indicated by CrlReason, i.e.CrlReason.KeyCompromise or 0 if CrlReason is not to be used
        /// </summary>
        /// <param name="userCertificate">The serial number of the certificate being revoked.</param>
        /// <param name="revocationDate">The date of revocation.</param>
        /// <param name="reason">The reason for revocation.</param>
        public void AddCrlEntry(
			BigInteger	userCertificate,
			DateTime	revocationDate,
			int			reason)
		{
			tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), reason);
        }

        /// <summary>
        /// Add a CRL entry with an Invalidity Date extension as well as a CrlReason extension.
		/// Reason being as indicated by CrlReason, i.e.CrlReason.KeyCompromise or 0 if CrlReason is not to be used
        /// </summary>
        /// <param name="userCertificate">The serial number of the certificate being revoked.</param>
        /// <param name="revocationDate">The date of revocation.</param>
        /// <param name="reason">The reason for revocation.</param>
        /// <param name="invalidityDate">The invalidity date.</param>
        public void AddCrlEntry(
			BigInteger	userCertificate,
			DateTime	revocationDate,
			int			reason,
			DateTime	invalidityDate)
		{
			tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), reason, new DerGeneralizedTime(invalidityDate));
		}

        /// <summary>
        /// Add a CRL entry with extensions.
        /// </summary>
        /// <param name="userCertificate">Serial number of certificate to be revoked.</param>
        /// <param name="revocationDate">Revocation date of the certificate.</param>
        /// <param name="extensions">The extensions to be associated with the CRL entry.</param>
        public void AddCrlEntry(
			BigInteger		userCertificate,
			DateTime		revocationDate,
			X509Extensions	extensions)
		{
			tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), extensions);
		}

        /// <summary>
        /// Add the CRLEntry objects contained in a previous CRL.
        /// </summary>
        /// <param name="other">A source CRL for CRL entry objects.</param>
        public void AddCrl(
			X509Crl other)
		{
			if (other == null)
				throw new ArgumentNullException("other");

			ISet revocations = other.GetRevokedCertificates();

			if (revocations != null)
			{
				foreach (X509CrlEntry entry in revocations)
				{
					try
					{
						tbsGen.AddCrlEntry(
							Asn1Sequence.GetInstance(
							Asn1Object.FromByteArray(entry.GetEncoded())));
					}
					catch (IOException e)
					{
						throw new CrlException("exception processing encoding of CRL", e);
					}
				}
			}
		}

        /// <summary>
        /// Add a given extension field for the standard extensions tag (tag 0)
        /// </summary>
        /// <param name="oid">The object identifier identifying the extension type.</param>
        /// <param name="critical">true if the extension should be regarded as critical, false otherwise.</param>
        /// <param name="extensionValue">The ASN.1 object to be encoded as the extension's value.</param>
        public void AddExtension(
			DerObjectIdentifier	oid,
			bool				critical,
			Asn1Encodable		extensionValue)
		{
			extGenerator.AddExtension(oid, critical, extensionValue);
		}

        /// <summary>
        /// Add a given extension field for the standard extensions tag (tag 0)
        /// </summary>
        /// <param name="oid">Its Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">byte[] containing the value of this extension.</param>
        public void AddExtension(
			DerObjectIdentifier	oid,
			bool				critical,
			byte[]				extensionValue)
		{
			extGenerator.AddExtension(oid, critical, extensionValue);
		}

        /// <summary>
        /// Generate a new X509CRL using the passed in SignatureCalculator.
        /// </summary>
		/// <param name="signatureCalculatorFactory">A signature calculator factory with the necessary algorithm details.</param>
        /// <returns>An X509CRL.</returns>
        public X509Crl Generate(ISignatureFactory<AlgorithmIdentifier> signatureCalculatorFactory)
        {
            tbsGen.SetSignature(signatureCalculatorFactory.AlgorithmDetails);

            TbsCertificateList tbsCertList = GenerateCertList();

            Crypto.IStreamCalculator<IBlockResult> streamCalculator = signatureCalculatorFactory.CreateCalculator();

            byte[] encoded = tbsCertList.GetDerEncoded();

            streamCalculator.Stream.Write(encoded, 0, encoded.Length);

            Platform.Dispose(streamCalculator.Stream);

            return GenerateJcaObject(tbsCertList, signatureCalculatorFactory.AlgorithmDetails, ((IBlockResult)streamCalculator.GetResult()).Collect());
        }

        private TbsCertificateList GenerateCertList()
		{
			if (!extGenerator.IsEmpty)
			{
				tbsGen.SetExtensions(extGenerator.Generate());
			}

			return tbsGen.GenerateTbsCertList();
		}

		private X509Crl GenerateJcaObject(
			TbsCertificateList	tbsCrl,
            AlgorithmIdentifier algId,
			byte[]				signature)
		{
			return new X509Crl(
				CertificateList.GetInstance(
					new DerSequence(tbsCrl, algId, new DerBitString(signature))));
		}
	}
}
