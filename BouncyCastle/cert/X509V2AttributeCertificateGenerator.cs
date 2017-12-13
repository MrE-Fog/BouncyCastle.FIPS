using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cert
{ 
	/// <remarks>Class to produce an X.509 Version 2 AttributeCertificate.</remarks>
	public class X509V2AttributeCertificateGenerator
	{
		private readonly X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

		private V2AttributeCertificateInfoGenerator	acInfoGen;
		private DerObjectIdentifier sigOID;
		private AlgorithmIdentifier sigAlgId;
		private string signatureAlgorithm;

		public X509V2AttributeCertificateGenerator()
		{
			acInfoGen = new V2AttributeCertificateInfoGenerator();
		}

		/// <summary>Reset the generator</summary>
		public void Reset()
		{
			acInfoGen = new V2AttributeCertificateInfoGenerator();
			extGenerator.Reset();
		}

		/// <summary>Set the Holder of this Attribute Certificate.</summary>
		public void SetHolder(
			AttributeCertificateHolder holder)
		{
			acInfoGen.SetHolder(holder.holder);
		}

		/// <summary>Set the issuer.</summary>
		public void SetIssuer(
			AttributeCertificateIssuer issuer)
		{
			acInfoGen.SetIssuer(AttCertIssuer.GetInstance(issuer.form));
		}

		/// <summary>Set the serial number for the certificate.</summary>
		public void SetSerialNumber(
			BigInteger serialNumber)
		{
			acInfoGen.SetSerialNumber(new DerInteger(serialNumber));
		}

		public void SetNotBefore(
			DateTime date)
		{
			acInfoGen.SetStartDate(new DerGeneralizedTime(date));
		}

		public void SetNotAfter(
			DateTime date)
		{
			acInfoGen.SetEndDate(new DerGeneralizedTime(date));
		}

		/// <summary>Add an attribute.</summary>
		public void AddAttribute(
			X509Attribute attribute)
		{
			acInfoGen.AddAttribute(AttributeX509.GetInstance(attribute.ToAsn1Object()));
		}

		public void SetIssuerUniqueId(
			bool[] iui)
		{
			// TODO convert bool array to bit string
			//acInfoGen.SetIssuerUniqueID(iui);
			throw Platform.CreateNotImplementedException("SetIssuerUniqueId()");
		}

		/// <summary>Add a given extension field for the standard extensions tag.</summary>
		public void AddExtension(
			string			oid,
			bool			critical,
			Asn1Encodable	extensionValue)
		{
			extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag.
		/// The value parameter becomes the contents of the octet string associated
		/// with the extension.
		/// </summary>
		public void AddExtension(
			string	oid,
			bool	critical,
			byte[]	extensionValue)
		{
			extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);
		}

        /// <summary>
        /// Generate a new X.509 Attribute Certificate using the passed in SignatureCalculator.
        /// </summary>
        /// <param name="signatureCalculatorFactory">A signature calculator factory with the necessary algorithm details.</param>
        /// <returns>An IX509AttributeCertificate.</returns>
        public X509V2AttributeCertificate Generate(ISignatureFactory<AlgorithmIdentifier> signatureCalculatorFactory)
        {
            if (!extGenerator.IsEmpty)
			{
				acInfoGen.SetExtensions(extGenerator.Generate());
			}

			AttributeCertificateInfo acInfo = acInfoGen.GenerateAttributeCertificateInfo();

            byte[] encoded = acInfo.GetDerEncoded();

            IStreamCalculator<IBlockResult> streamCalculator = signatureCalculatorFactory.CreateCalculator();

            streamCalculator.Stream.Write(encoded, 0, encoded.Length);

            Platform.Dispose(streamCalculator.Stream);

            Asn1EncodableVector v = new Asn1EncodableVector();

			v.Add(acInfo, signatureCalculatorFactory.AlgorithmDetails);

			try
			{
				v.Add(new DerBitString(streamCalculator.GetResult().Collect()));

				return new X509V2AttributeCertificate(AttributeCertificate.GetInstance(new DerSequence(v)));
			}
			catch (Exception e)
			{
				// TODO
//				throw new ExtCertificateEncodingException("constructed invalid certificate", e);
				throw new CertificateEncodingException("constructed invalid certificate", e);
			}
		}
	}
}
