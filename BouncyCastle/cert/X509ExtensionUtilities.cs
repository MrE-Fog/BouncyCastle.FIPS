using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Cert
{
    /// <summary>
    /// General utility methods for generating X.509 certificates.
    /// </summary>
	public class X509ExtensionUtilities
	{
        private IDigestFactory<FipsShs.Parameters> digestFactory;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="digestFactory">The digest factory to base key info/identifier calculations on.</param>
        public X509ExtensionUtilities(IDigestFactory<FipsShs.Parameters> digestFactory)
        {
            this.digestFactory = digestFactory;
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier from the passed in arguments.
        /// </summary>
        /// <param name="certHolder">the issuer certificate that the AuthorityKeyIdentifier should refer to.</param>
        /// <returns>an AuthorityKeyIdentifier.</returns>
        public AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(
            X509Certificate certHolder)
        {
            GeneralName genName = new GeneralName(certHolder.IssuerDN);

            return new AuthorityKeyIdentifier(
                    getSubjectKeyIdentifier(certHolder), new GeneralNames(genName), certHolder.SerialNumber);
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier from the passed in public key.
        /// </summary>
        /// <param name="publicKey">the public key to base the key identifier on.</param>
        /// <returns>an AuthorityKeyIdentifier.</returns>
        public AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(IAsymmetricPublicKey publicKey)
        {
            return new AuthorityKeyIdentifier(calculateIdentifier(SubjectPublicKeyInfo.GetInstance(publicKey.GetEncoded())));
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier from the passed in SubjectPublicKeyInfo.
        /// </summary>
        /// <param name="publicKeyInfo">the SubjectPublicKeyInfo to base the key identifier on.</param>
        /// <returns>an AuthorityKeyIdentifier.</returns>
        public AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
        {
            return new AuthorityKeyIdentifier(calculateIdentifier(publicKeyInfo));
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier from the passed in arguments.
        /// </summary>
        /// <param name="publicKeyInfo">the SubjectPublicKeyInfo to base the key identifier on.</param>
        /// <param name="generalNames">the general names to associate with the issuer cert's issuer.</param>
        /// <param name="serial">the serial number of the issuer cert.</param>
        /// <returns>an AuthorityKeyIdentifier.</returns>
        public AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo, GeneralNames generalNames, BigInteger serial)
        {
            return new AuthorityKeyIdentifier(calculateIdentifier(publicKeyInfo), generalNames, serial);
        }

        /// <summary>
        /// Return a RFC 5280 type 1 key identifier. As in: "(1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
        /// value of the BIT STRING subjectPublicKey(excluding the tag, length, and number of unused bits)."
        /// </summary>
        /// <param name="publicKey">the public key to base the identifier on.</param>
        /// <returns>the key identifier.</returns>
        public SubjectKeyIdentifier CreateSubjectKeyIdentifier(IAsymmetricPublicKey publicKey)
        {
            return CreateSubjectKeyIdentifier(SubjectPublicKeyInfo.GetInstance(publicKey.GetEncoded()));
        }

        /// <summary>
        /// Return a RFC 5280 type 1 key identifier. As in: "(1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
        /// value of the BIT STRING subjectPublicKey(excluding the tag, length, and number of unused bits)."
        /// </summary>
        /// <param name="publicKeyInfo">the key info object containing the subjectPublicKey field.</param>
        /// <returns>the key identifier.</returns>
        public SubjectKeyIdentifier CreateSubjectKeyIdentifier(
            SubjectPublicKeyInfo publicKeyInfo)
        {
            return new SubjectKeyIdentifier(calculateIdentifier(publicKeyInfo));
        }

        /// <summary>
        /// Return a RFC 5280 type 2 key identifier. As in: "(2) The keyIdentifier is composed of a four bit type field with
        /// the value 0100 followed by the least significant 60 bits of the SHA-1 hash of the value of the BIT STRING subjectPublicKey.
        /// </summary>
        /// <param name="publicKeyInfo">the key info object containing the subjectPublicKey field.</param>
        /// <returns>the key identifier.</returns>
        public SubjectKeyIdentifier CreateTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo publicKeyInfo)
        {
            byte[] digest = calculateIdentifier(publicKeyInfo);
            byte[] id = new byte[8];

            Array.Copy(digest, digest.Length - 8, id, 0, id.Length);

            id[0] &= 0x0f;
            id[0] |= 0x40;

            return new SubjectKeyIdentifier(id);
        }

        private byte[] getSubjectKeyIdentifier(X509Certificate certHolder)
        {
            if (certHolder.Version != 3)
            {
                return calculateIdentifier(certHolder.ToAsn1Structure().SubjectPublicKeyInfo);
            }
            else
            {
                byte[] ext = certHolder.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);

                if (ext != null)
                {
                    return Asn1OctetString.GetInstance(ext).GetOctets();
                }
                else
                {
                    return calculateIdentifier(certHolder.ToAsn1Structure().SubjectPublicKeyInfo);
                }
            }
        }

        private byte[] calculateIdentifier(SubjectPublicKeyInfo publicKeyInfo)
        {
            byte[] bytes = publicKeyInfo.PublicKeyData.GetBytes();

            IStreamCalculator<IBlockResult> calculator = digestFactory.CreateCalculator();

            Stream cOut = calculator.Stream;

            try
            {
                cOut.Write(bytes, 0, bytes.Length);

                cOut.Close();
            }
            catch (IOException e)
            {   // it's hard to imagine this happening, but yes it does!
                throw new CertificateException("unable to calculate identifier: " + e.Message, e);
            }

            return calculator.GetResult().Collect();
        }

        internal static ICollection GetIssuerAlternativeNames(
			X509Certificate cert)
		{
			byte[] extVal = cert.GetExtensionValue(X509Extensions.IssuerAlternativeName);

			return GetAlternativeName(extVal);
		}

        internal static ICollection GetSubjectAlternativeNames(
			X509Certificate cert)
		{
			byte[] extVal = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);

			return GetAlternativeName(extVal);
		}

        internal static ICollection GetAlternativeName(
			byte[] extVal)
		{
			IList temp = Platform.CreateArrayList();

			if (extVal != null)
			{
				try
				{
					Asn1Sequence seq = Asn1Sequence.GetInstance(extVal);

					foreach (GeneralName genName in seq)
					{
                        IList list = Platform.CreateArrayList();
						list.Add(genName.TagNo);

						switch (genName.TagNo)
						{
							case GeneralName.EdiPartyName:
							case GeneralName.X400Address:
							case GeneralName.OtherName:
								list.Add(genName.Name.ToAsn1Object());
								break;
							case GeneralName.DirectoryName:
								list.Add(X500Name.GetInstance(genName.Name).ToString());
								break;
							case GeneralName.DnsName:
							case GeneralName.Rfc822Name:
							case GeneralName.UniformResourceIdentifier:
								list.Add(((IAsn1String)genName.Name).GetString());
								break;
							case GeneralName.RegisteredID:
								list.Add(DerObjectIdentifier.GetInstance(genName.Name).Id);
								break;
							case GeneralName.IPAddress:
								list.Add(DerOctetString.GetInstance(genName.Name).GetOctets());
								break;
							default:
								throw new IOException("Bad tag number: " + genName.TagNo);
						}

						temp.Add(list);
					}
				}
				catch (Exception e)
				{
					throw new CertificateParsingException(e.Message);
				}
			}

			return temp;
		}
    }
}
