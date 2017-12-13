using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cert
{ 
    /// <summary>
    /// A class to Generate Version 3 X509Certificates.
    /// </summary>
    public class X509V3CertificateGenerator
    {
		private readonly X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

		private V3TbsCertificateGenerator	tbsGen;

        /// <summary>
        /// Base constructor.
        /// </summary>
		public X509V3CertificateGenerator()
        {
            tbsGen = new V3TbsCertificateGenerator();
        }

		/// <summary>
		/// Reset the Generator.
		/// </summary>
		public void Reset()
		{
			tbsGen = new V3TbsCertificateGenerator();
			extGenerator.Reset();
		}

		/// <summary>
        /// Set the certificate's serial number.
        /// </summary>
        /// <remarks>Make serial numbers long, if you have no serial number policy make sure the number is at least 16 bytes of secure random data.
        /// You will be surprised how ugly a serial number collision can Get.</remarks>
        /// <param name="serialNumber">The serial number.</param>
        public void SetSerialNumber(
			BigInteger serialNumber)
        {
			if (serialNumber.SignValue <= 0)
			{
				throw new ArgumentException("serial number must be a positive integer", "serialNumber");
			}

			tbsGen.SetSerialNumber(new DerInteger(serialNumber));
        }

		/// <summary>
        /// Set the distinguished name of the issuer.
        /// The issuer is the entity which is signing the certificate.
        /// </summary>
        /// <param name="issuer">The issuer's DN.</param>
        public void SetIssuerDN(
            X500Name issuer)
        {
            tbsGen.SetIssuer(issuer);
        }

        /// <summary>
        /// Set the date that this certificate is to be valid from.
        /// </summary>
        /// <param name="date">Date from which a generated certificate is valid.</param>
        public void SetNotBefore(
            DateTime date)
        {
            tbsGen.SetStartDate(new Time(date));
        }

        /// <summary>
        /// Set the date after which this certificate will no longer be valid.
        /// </summary>
        /// <param name="date">Date after which a generated certificate will expire.</param>
        public void SetNotAfter(
			DateTime date)
        {
            tbsGen.SetEndDate(new Time(date));
        }

        /// <summary>
        /// Set the DN of the entity that is represented by the generated certificate's public key.
        /// </summary>
		/// <param name="subject">The X.500 name of the generated certificate's subject.</param>
        public void SetSubjectDN(
			X500Name subject)
        {
            tbsGen.SetSubject(subject);
        }

		/// <summary>
        /// Set the public key that this certificate identifies.
        /// </summary>
        /// <param name="publicKey">The public key to be carried by the generated certificate.</param>
        public void SetPublicKey(
			IAsymmetricPublicKey publicKey)
        {
            tbsGen.SetSubjectPublicKeyInfo(SubjectPublicKeyInfo.GetInstance(publicKey.GetEncoded()));
        }

        /// <summary>
        /// Set the subject unique ID - note: it is very rare that it is correct to do this.
        /// </summary>
        /// <param name="uniqueID">The subject unique ID.</param>
        public void SetSubjectUniqueID(
			bool[] uniqueID)
		{
			tbsGen.SetSubjectUniqueID(booleanToBitString(uniqueID));
		}

		/// <summary>
		/// Set the issuer unique ID - note: it is very rare that it is correct to do this.
		/// </summary>
		/// <param name="uniqueID">The issuer unique ID.</param>
		public void SetIssuerUniqueID(
			bool[] uniqueID)
		{
			tbsGen.SetIssuerUniqueID(booleanToBitString(uniqueID));
		}

		private DerBitString booleanToBitString(
			bool[] id)
		{
			byte[] bytes = new byte[(id.Length + 7) / 8];

			for (int i = 0; i != id.Length; i++)
			{
				if (id[i])
				{
					bytes[i / 8] |= (byte)(1 << ((7 - (i % 8))));
				}
			}

			int pad = id.Length % 8;

			if (pad == 0)
			{
				return new DerBitString(bytes);
			}

			return new DerBitString(bytes, 8 - pad);
		}

        /// <summary>
        /// Add the given extension details to the certificate.
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
        /// Add an extension to this certificate.
        /// </summary>
        /// <param name="oid">Its Object Identifier.</param>
        /// <param name="critical">true, if the extension should be regarded as critical critical.</param>
        /// <param name="extensionValue">byte[] containing the value octets of this extension.</param>
        public void AddExtension(
			DerObjectIdentifier	oid,
			bool				critical,
			byte[]				extensionValue)
        {
			extGenerator.AddExtension(oid, critical, extensionValue);
        }

        /// <summary>
        /// Add a given extension field for the standard extensions tag (tag 3),
        /// copying the extension value from another certificate.
        /// </summary>
        /// <param name="oid">The object identifier of the extension to be copied.</param>
        /// <param name="critical">true, if the copied extension should be regarded as critical critical.</param>
        /// <param name="cert">The source certificate to copy the extension from.</param>
        /// <exception cref="CertificateParsingException">If the extension cannot be extracted.</exception>
        public void CopyAndAddExtension(
			DerObjectIdentifier	oid,
			bool				critical,
			X509Certificate		cert)
		{
			byte[] extValue = cert.GetExtensionValue(oid);

			if (extValue == null)
			{
				throw new CertificateParsingException("extension " + oid + " not present");
			}

			try
			{
				Asn1Encodable value = Asn1Object.FromByteArray(extValue);

				this.AddExtension(oid, critical, value);
			}
			catch (Exception e)
			{
				throw new CertificateParsingException(e.Message, e);
			}
		}

		/// <summary>
		/// Generate a new X509Certificate using the passed in SignatureCalculator.
		/// </summary>
		/// <param name="signatureCalculatorFactory">A signature calculator factory with the necessary algorithm details.</param>
		/// <returns>An X509Certificate.</returns>
		public X509Certificate Generate(ISignatureFactory<AlgorithmIdentifier> signatureCalculatorFactory)
		{
			tbsGen.SetSignature (signatureCalculatorFactory.AlgorithmDetails);

            if (!extGenerator.IsEmpty)
            {
                tbsGen.SetExtensions(extGenerator.Generate());
            }

            TbsCertificateStructure tbsCert = tbsGen.GenerateTbsCertificate();

			IStreamCalculator<IBlockResult> streamCalculator = signatureCalculatorFactory.CreateCalculator();

			byte[] encoded = tbsCert.GetDerEncoded();

			streamCalculator.Stream.Write(encoded, 0, encoded.Length);

            Platform.Dispose(streamCalculator.Stream);

            return GenerateJcaObject(tbsCert, signatureCalculatorFactory.AlgorithmDetails, ((IBlockResult)streamCalculator.GetResult()).Collect());
		}

		private X509Certificate GenerateJcaObject(
			TbsCertificateStructure	tbsCert,
			AlgorithmIdentifier     sigAlg,
			byte[]					signature)
		{
			return new X509Certificate(
				new X509CertificateStructure(tbsCert, sigAlg, new DerBitString(signature)));
		}
	}
}
