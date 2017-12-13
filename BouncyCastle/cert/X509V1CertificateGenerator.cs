using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cert
{
	/// <summary>
	/// Class to Generate X509V1 Certificates.
	/// </summary>
	public class X509V1CertificateGenerator
	{
		private V1TbsCertificateGenerator   tbsGen;

		/// <summary>
		/// Default Constructor.
		/// </summary>
		public X509V1CertificateGenerator()
		{
			tbsGen = new V1TbsCertificateGenerator();
		}

		/// <summary>
		/// Reset the generator.
		/// </summary>
		public void Reset()
		{
			tbsGen = new V1TbsCertificateGenerator();
		}

		/// <summary>
		/// Set the certificate's serial number.
		/// </summary>
		/// <remarks>Make serial numbers long, if you have no serial number policy make sure the number is at least 16 bytes of secure random data.
		/// You will be surprised how ugly a serial number collision can get.</remarks>
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
		/// Set the issuer distinguished name.
		/// The issuer is the entity whose private key is used to sign the certificate.
		/// </summary>
		/// <param name="issuer">The issuers DN.</param>
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
			try
			{
				tbsGen.SetSubjectPublicKeyInfo(SubjectPublicKeyInfo.GetInstance(publicKey.GetEncoded()));
			}
			catch (Exception e)
			{
				throw new ArgumentException("unable to process key - " + e.ToString());
			}
		}

		/// <summary>
		/// Generate a new X509Certificate using the passed in SignatureCalculator.
		/// </summary>
		/// <param name="signatureCalculatorFactory">A signature calculator factory with the necessary algorithm details.</param>
		/// <returns>An X509Certificate.</returns>
		public X509Certificate Generate(ISignatureFactory<AlgorithmIdentifier> signatureCalculatorFactory)
		{
			tbsGen.SetSignature ((AlgorithmIdentifier)signatureCalculatorFactory.AlgorithmDetails);

			TbsCertificateStructure tbsCert = tbsGen.GenerateTbsCertificate();

            IStreamCalculator<IBlockResult> streamCalculator = signatureCalculatorFactory.CreateCalculator();

            byte[] encoded = tbsCert.GetDerEncoded();

            streamCalculator.Stream.Write(encoded, 0, encoded.Length);

            Platform.Dispose(streamCalculator.Stream);

            return GenerateJcaObject(tbsCert, (AlgorithmIdentifier)signatureCalculatorFactory.AlgorithmDetails, ((IBlockResult)streamCalculator.GetResult()).Collect());
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
