using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Cert;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    internal class CmsSignedHelper
    {
        internal static readonly CmsSignedHelper Instance = new CmsSignedHelper();

        private static readonly string EncryptionECDsaWithSha1 = X9ObjectIdentifiers.ECDsaWithSha1.Id;
        private static readonly string EncryptionECDsaWithSha224 = X9ObjectIdentifiers.ECDsaWithSha224.Id;
        private static readonly string EncryptionECDsaWithSha256 = X9ObjectIdentifiers.ECDsaWithSha256.Id;
        private static readonly string EncryptionECDsaWithSha384 = X9ObjectIdentifiers.ECDsaWithSha384.Id;
        private static readonly string EncryptionECDsaWithSha512 = X9ObjectIdentifiers.ECDsaWithSha512.Id;

        private static readonly IDictionary encryptionAlgs = Platform.CreateHashtable();
        private static readonly IDictionary digestAlgs = Platform.CreateHashtable();
        private static readonly IDictionary digestAliases = Platform.CreateHashtable();

        private static readonly ISet noParams = new HashSet();
        private static readonly IDictionary ecAlgorithms = Platform.CreateHashtable();

        private static void AddEntries(DerObjectIdentifier oid, string digest, string encryption)
		{
			string alias = oid.Id;
			digestAlgs.Add(alias, digest);
			encryptionAlgs.Add(alias, encryption);
		}

		static CmsSignedHelper()
		{
			AddEntries(NistObjectIdentifiers.DsaWithSha224, "SHA224", "DSA");
			AddEntries(NistObjectIdentifiers.DsaWithSha256, "SHA256", "DSA");
			AddEntries(NistObjectIdentifiers.DsaWithSha384, "SHA384", "DSA");
			AddEntries(NistObjectIdentifiers.DsaWithSha512, "SHA512", "DSA");
			AddEntries(OiwObjectIdentifiers.DsaWithSha1, "SHA1", "DSA");
			AddEntries(OiwObjectIdentifiers.MD4WithRsa, "MD4", "RSA");
			AddEntries(OiwObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
			AddEntries(OiwObjectIdentifiers.MD5WithRsa, "MD5", "RSA");
			AddEntries(OiwObjectIdentifiers.Sha1WithRsa, "SHA1", "RSA");
			AddEntries(PkcsObjectIdentifiers.MD2WithRsaEncryption, "MD2", "RSA");
			AddEntries(PkcsObjectIdentifiers.MD4WithRsaEncryption, "MD4", "RSA");
			AddEntries(PkcsObjectIdentifiers.MD5WithRsaEncryption, "MD5", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha1WithRsaEncryption, "SHA1", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha224WithRsaEncryption, "SHA224", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha256WithRsaEncryption, "SHA256", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha384WithRsaEncryption, "SHA384", "RSA");
			AddEntries(PkcsObjectIdentifiers.Sha512WithRsaEncryption, "SHA512", "RSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha1, "SHA1", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha224, "SHA224", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha256, "SHA256", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha384, "SHA384", "ECDSA");
			AddEntries(X9ObjectIdentifiers.ECDsaWithSha512, "SHA512", "ECDSA");
			AddEntries(X9ObjectIdentifiers.IdDsaWithSha1, "SHA1", "DSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
			AddEntries(EacObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");

			encryptionAlgs.Add(X9ObjectIdentifiers.IdDsa.Id, "DSA");
			encryptionAlgs.Add(PkcsObjectIdentifiers.RsaEncryption.Id, "RSA");
			encryptionAlgs.Add(TeleTrusTObjectIdentifiers.TeleTrusTRsaSignatureAlgorithm, "RSA");
			encryptionAlgs.Add(X509ObjectIdentifiers.IdEARsa.Id, "RSA");
			encryptionAlgs.Add(CmsSignedGenerator.EncryptionRsaPss, "RSAandMGF1");
			encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x94.Id, "GOST3410");
			encryptionAlgs.Add(CryptoProObjectIdentifiers.GostR3410x2001.Id, "ECGOST3410");
			encryptionAlgs.Add("1.3.6.1.4.1.5849.1.6.2", "ECGOST3410");
			encryptionAlgs.Add("1.3.6.1.4.1.5849.1.1.5", "GOST3410");

			digestAlgs.Add(PkcsObjectIdentifiers.MD2.Id, "MD2");
			digestAlgs.Add(PkcsObjectIdentifiers.MD4.Id, "MD4");
			digestAlgs.Add(PkcsObjectIdentifiers.MD5.Id, "MD5");
			digestAlgs.Add(OiwObjectIdentifiers.IdSha1.Id, "SHA1");
			digestAlgs.Add(NistObjectIdentifiers.IdSha224.Id, "SHA224");
			digestAlgs.Add(NistObjectIdentifiers.IdSha256.Id, "SHA256");
			digestAlgs.Add(NistObjectIdentifiers.IdSha384.Id, "SHA384");
			digestAlgs.Add(NistObjectIdentifiers.IdSha512.Id, "SHA512");
			digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD128.Id, "RIPEMD128");
			digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD160.Id, "RIPEMD160");
			digestAlgs.Add(TeleTrusTObjectIdentifiers.RipeMD256.Id, "RIPEMD256");
			digestAlgs.Add(CryptoProObjectIdentifiers.GostR3411.Id,  "GOST3411");
			digestAlgs.Add("1.3.6.1.4.1.5849.1.2.1",  "GOST3411");

			digestAliases.Add("SHA1", new string[] { "SHA-1" });
			digestAliases.Add("SHA224", new string[] { "SHA-224" });
			digestAliases.Add("SHA256", new string[] { "SHA-256" });
			digestAliases.Add("SHA384", new string[] { "SHA-384" });
			digestAliases.Add("SHA512", new string[] { "SHA-512" });

            noParams.Add(CmsSignedGenerator.EncryptionDsa);
            //			noParams.Add(EncryptionECDsa);
            noParams.Add(EncryptionECDsaWithSha1);
            noParams.Add(EncryptionECDsaWithSha224);
            noParams.Add(EncryptionECDsaWithSha256);
            noParams.Add(EncryptionECDsaWithSha384);
            noParams.Add(EncryptionECDsaWithSha512);

            ecAlgorithms.Add(CmsSignedGenerator.DigestSha1, EncryptionECDsaWithSha1);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha224, EncryptionECDsaWithSha224);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha256, EncryptionECDsaWithSha256);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha384, EncryptionECDsaWithSha384);
            ecAlgorithms.Add(CmsSignedGenerator.DigestSha512, EncryptionECDsaWithSha512);
    }

		/**
        * Return the digest algorithm using one of the standard JCA string
        * representations rather than the algorithm identifier (if possible).
        */
        internal string GetDigestAlgName(
            string digestAlgOid)
        {
			string algName = (string)digestAlgs[digestAlgOid];

			if (algName != null)
			{
				return algName;
			}

			return digestAlgOid;
        }

    internal AlgorithmIdentifier GetEncAlgorithmIdentifier(
    DerObjectIdentifier encOid,
    Asn1Encodable sigX509Parameters)
    {
        if (noParams.Contains(encOid.Id))
        {
            return new AlgorithmIdentifier(encOid);
        }

        return new AlgorithmIdentifier(encOid, sigX509Parameters);
    }

    internal string[] GetDigestAliases(
			string algName)
		{
			string[] aliases = (string[]) digestAliases[algName];

			return aliases == null ? new String[0] : (string[]) aliases.Clone();
		}

		/**
        * Return the digest encryption algorithm using one of the standard
        * JCA string representations rather than the algorithm identifier (if
        * possible).
        */
        internal string GetEncryptionAlgName(
            string encryptionAlgOid)
        {
			string algName = (string) encryptionAlgs[encryptionAlgOid];

			if (algName != null)
			{
				return algName;
			}

			return encryptionAlgOid;
        }

		internal IStore<X509V2AttributeCertificate> CreateAttributeStore(
			Asn1Set	certSet)
		{
			IList<X509V2AttributeCertificate> certs = new List<X509V2AttributeCertificate>();

			if (certSet != null)
			{
				foreach (Asn1Encodable ae in certSet)
				{
					try
					{
						Asn1Object obj = ae.ToAsn1Object();

						if (obj is Asn1TaggedObject)
						{
							Asn1TaggedObject tagged = (Asn1TaggedObject)obj;

							if (tagged.TagNo == 2)
							{
								certs.Add(
									new X509V2AttributeCertificate(
										Asn1Sequence.GetInstance(tagged, false).GetEncoded()));
							}
						}
					}
					catch (Exception ex)
					{
						throw new CmsException("can't re-encode attribute certificate!", ex);
					}
				}
			}

			try
			{
				return new CollectionStore<X509V2AttributeCertificate>(certs);
			}
			catch (ArgumentException e)
			{
				throw new CmsException("can't setup the X509Store", e);
			}
		}

		internal IStore<X509Certificate> CreateCertificateStore(
			Asn1Set	certSet)
		{
            IList<X509Certificate> certs = new List<X509Certificate>();

            if (certSet != null)
			{
				AddCertsFromSet(certs, certSet);
			}

			try
			{
                return new CollectionStore<X509Certificate>(certs);
            }
			catch (ArgumentException e)
			{
				throw new CmsException("can't setup the X509Store", e);
			}
		}

		internal IStore<X509Crl> CreateCrlStore(
			Asn1Set	crlSet)
		{
            IList<X509Crl> crls = new List<X509Crl>();

            if (crlSet != null)
			{
				AddCrlsFromSet(crls, crlSet);
			}

			try
			{
                return new CollectionStore<X509Crl>(crls);
            }
			catch (ArgumentException e)
			{
				throw new CmsException("can't setup the X509Store", e);
			}
		}

		private void AddCertsFromSet(
			IList<X509Certificate>	certs,
			Asn1Set	certSet)
		{
			foreach (Asn1Encodable ae in certSet)
			{
				try
				{
					Asn1Object obj = ae.ToAsn1Object();

					if (obj is Asn1Sequence)
					{
						certs.Add(new X509Certificate(obj.GetEncoded()));
					}
				}
				catch (Exception ex)
				{
					throw new CmsException("can't re-encode certificate!", ex);
				}
			}
		}

		private void AddCrlsFromSet(
			IList<X509Crl>	crls,
			Asn1Set	crlSet)
		{
			foreach (Asn1Encodable ae in crlSet)
			{
				try
				{
					crls.Add(new X509Crl(ae.GetEncoded()));
				}
				catch (Exception ex)
				{
					throw new CmsException("can't re-encode CRL!", ex);
				}
			}
		}

		internal AlgorithmIdentifier FixAlgID(
			AlgorithmIdentifier algId)
		{
			if (algId.Parameters == null)
                return new AlgorithmIdentifier(algId.Algorithm, DerNull.Instance);

			return algId;
		}
    }
}
