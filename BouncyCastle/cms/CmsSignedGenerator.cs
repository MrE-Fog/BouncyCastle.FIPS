using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Cert;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    public class CmsSignedGenerator
    {
        /**
        * Default type for the signed data.
        */
        public static readonly string Data = CmsObjectIdentifiers.Data.Id;

        public static readonly string DigestSha1 = OiwObjectIdentifiers.IdSha1.Id;
        public static readonly string DigestSha224 = NistObjectIdentifiers.IdSha224.Id;
        public static readonly string DigestSha256 = NistObjectIdentifiers.IdSha256.Id;
        public static readonly string DigestSha384 = NistObjectIdentifiers.IdSha384.Id;
        public static readonly string DigestSha512 = NistObjectIdentifiers.IdSha512.Id;
        public static readonly string DigestMD5 = PkcsObjectIdentifiers.MD5.Id;
        public static readonly string DigestGost3411 = CryptoProObjectIdentifiers.GostR3411.Id;
        public static readonly string DigestRipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128.Id;
        public static readonly string DigestRipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160.Id;
        public static readonly string DigestRipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256.Id;

        public static readonly string EncryptionRsa = PkcsObjectIdentifiers.RsaEncryption.Id;
        public static readonly string EncryptionDsa = X9ObjectIdentifiers.IdDsaWithSha1.Id;
        public static readonly string EncryptionECDsa = X9ObjectIdentifiers.ECDsaWithSha1.Id;
        public static readonly string EncryptionRsaPss = PkcsObjectIdentifiers.IdRsassaPss.Id;
        public static readonly string EncryptionGost3410 = CryptoProObjectIdentifiers.GostR3410x94.Id;
        public static readonly string EncryptionECGost3410 = CryptoProObjectIdentifiers.GostR3410x2001.Id;

        internal IList _certs = Platform.CreateArrayList();
        internal IList _crls = Platform.CreateArrayList();
        internal IList _signers = Platform.CreateArrayList();
        internal IDictionary _digests = Platform.CreateHashtable();
        internal IList _signerGens = new ArrayList();

        protected CmsSignedGenerator()
        {
        }

        internal protected virtual IDictionary<string, object> GetBaseParameters(
            DerObjectIdentifier contentType,
            AlgorithmIdentifier digAlgId,
            byte[] hash)
        {
            IDictionary<string, object> param = new Dictionary<string, object>();

            if (contentType != null)
            {
                param[CmsAttributeTableParameter.ContentType] = contentType;
            }

            param[CmsAttributeTableParameter.DigestAlgorithmIdentifier] = digAlgId;
            param[CmsAttributeTableParameter.Digest] = hash.Clone();

            return param;
        }

        internal protected virtual Asn1Set GetAttributeSet(
            Asn1.Cms.AttributeTable attr)
        {
            return attr == null
                ? null
                : new DerSet(attr.ToAsn1EncodableVector());
        }

        public void AddCertificates(
            IStore<X509Certificate> certStore)
        {
            CollectionUtilities.AddRange(_certs, CmsUtilities.GetCertificatesFromStore(certStore));
        }

        public void AddCrls(
            IStore<X509Crl> crlStore)
        {
            CollectionUtilities.AddRange(_crls, CmsUtilities.GetCrlsFromStore(crlStore));
        }

        /**
		* Add the attribute certificates contained in the passed in store to the
		* generator.
		*
		* @param store a store of Version 2 attribute certificates
		* @throws CmsException if an error occurse processing the store.
		*/
        public void AddAttributeCertificates(
            IStore<X509V2AttributeCertificate> store)
        {
            try
            {
                foreach (X509V2AttributeCertificate attrCert in store.GetMatches(null))
                {
                    _certs.Add(new DerTaggedObject(false, 2,
                        AttributeCertificate.GetInstance(Asn1Object.FromByteArray(attrCert.GetEncoded()))));
                }
            }
            catch (Exception e)
            {
                throw new CmsException("error processing attribute certs", e);
            }
        }

        /**
		 * Add a store of precalculated signers to the generator.
		 *
		 * @param signerStore store of signers
		 */
        public void AddSigners(
            SignerInformationStore signerStore)
        {
            foreach (SignerInformation o in signerStore.GetAll())
            {
                _signers.Add(o);
            }
        }

        /**
		 * Return a map of oids and byte arrays representing the digests calculated on the content during
		 * the last generate.
		 *
		 * @return a map of oids (as String objects) and byte[] representing digests.
		 */
        public IDictionary GetGeneratedDigests()
        {
            return Platform.CreateHashtable(_digests);
        }

        public void AddSignerInfoGenerator(SignerInfoGenerator signerInfoGenerator)
        {
            _signerGens.Add(signerInfoGenerator);
        }

        internal static SignerIdentifier GetSignerIdentifier(X509Certificate cert)
        {
            return new SignerIdentifier(CmsUtilities.GetIssuerAndSerialNumber(cert));
        }

        internal static SignerIdentifier GetSignerIdentifier(byte[] subjectKeyIdentifier)
        {
            return new SignerIdentifier(new DerOctetString(subjectKeyIdentifier));
        }
    }
}
