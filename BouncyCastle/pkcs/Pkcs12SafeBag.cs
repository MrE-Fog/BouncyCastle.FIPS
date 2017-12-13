using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;

namespace Org.BouncyCastle.Pkcs
{
    public class Pkcs12SafeBag
    {
        public static readonly DerObjectIdentifier FriendlyNameAttribute = PkcsObjectIdentifiers.Pkcs9AtFriendlyName;
        public static readonly DerObjectIdentifier LocalKeyIdAttribute = PkcsObjectIdentifiers.Pkcs9AtLocalKeyID;

        private SafeBag safeBag;

        public Pkcs12SafeBag(SafeBag safeBag)
        {
            this.safeBag = safeBag;
        }

        /**
         * Return the underlying ASN.1 structure for this safe bag.
         *
         * @return a SafeBag
         */
        public SafeBag ToAsn1Structure()
        {
            return safeBag;
        }

        /**
         * Return the BagId giving the type of content in the bag.
         *
         * @return the bagId
         */
        public DerObjectIdentifier Type
        {
            get
            {
                return safeBag.BagID;
            }
        }

        public AttributePkcs[] GetAttributes()
        {
            Asn1Set attrs = safeBag.BagAttributes;

            if (attrs == null)
            {
                return null;
            }

            AttributePkcs[] attributes = new AttributePkcs[attrs.Count];
            for (int i = 0; i != attrs.Count; i++)
            {
                attributes[i] = AttributePkcs.GetInstance(attrs[i]);
            }

            return attributes;
        }

        public object GetBagValue()
        {
            if (Type.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
            {
                return new Pkcs8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.GetInstance(safeBag.BagValue));
            }
            if (Type.Equals(PkcsObjectIdentifiers.CertBag))
            {
                CertBag certBag = CertBag.GetInstance(safeBag.BagValue);

                return new X509Certificate(X509CertificateStructure.GetInstance(Asn1OctetString.GetInstance(certBag.CertValue).GetOctets()));
            }
            if (Type.Equals(PkcsObjectIdentifiers.KeyBag))
            {
                return PrivateKeyInfo.GetInstance(safeBag.BagValue);
            }
            if (Type.Equals(PkcsObjectIdentifiers.CrlBag))
            {
                CrlBag crlBag = CrlBag.GetInstance(safeBag.BagValue);

                return new X509Crl(CertificateList.GetInstance(Asn1OctetString.GetInstance(crlBag.CrlValue).GetOctets()));
            }

            return safeBag.BagValue;
        }
    }
}
