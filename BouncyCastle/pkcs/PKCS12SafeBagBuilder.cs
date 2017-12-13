using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkcs
{

    public class Pkcs12SafeBagBuilder
    {
        private DerObjectIdentifier bagType;
        private Asn1Encodable bagValue;
        private Asn1EncodableVector bagAttrs = new Asn1EncodableVector();

        public Pkcs12SafeBagBuilder(IAsymmetricPrivateKey privateKey, ICipherBuilder<AlgorithmIdentifier> encryptor): this(PrivateKeyInfo.GetInstance(privateKey.GetEncoded()), encryptor)
        {
        }

        public Pkcs12SafeBagBuilder(PrivateKeyInfo privateKeyInfo, ICipherBuilder<AlgorithmIdentifier> encryptor)
        {
            this.bagType = PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag;
            this.bagValue = new Pkcs8EncryptedPrivateKeyInfoBuilder(privateKeyInfo).Build(encryptor).ToAsn1Structure();
        }

        public Pkcs12SafeBagBuilder(PrivateKeyInfo privateKeyInfo)
        {
            this.bagType = PkcsObjectIdentifiers.KeyBag;
            this.bagValue = privateKeyInfo;
        }

        public Pkcs12SafeBagBuilder(IAsymmetricPrivateKey privateKey): this(PrivateKeyInfo.GetInstance(privateKey.GetEncoded()))
        {
        }

        public Pkcs12SafeBagBuilder(X509Certificate certificate) : this(certificate.ToAsn1Structure())
        {
        }

        public Pkcs12SafeBagBuilder(X509Crl crl) : this(crl.ToAsn1Structure())
        {

        }

        public Pkcs12SafeBagBuilder(X509CertificateStructure certificate)
        {
            this.bagType = PkcsObjectIdentifiers.CertBag;
            this.bagValue = new CertBag(PkcsObjectIdentifiers.X509Certificate, new DerOctetString(certificate.GetEncoded()));
        }

        public Pkcs12SafeBagBuilder(CertificateList crl)
        {
            this.bagType = PkcsObjectIdentifiers.CrlBag;
            this.bagValue = new CertBag(PkcsObjectIdentifiers.X509Crl, new DerOctetString(crl.GetEncoded()));
        }

        public Pkcs12SafeBagBuilder AddBagAttribute(DerObjectIdentifier attrType, Asn1Encodable attrValue)
        {
            bagAttrs.Add(new AttributePkcs(attrType, new DerSet(attrValue)));

            return this;
        }

        public Pkcs12SafeBag Build()
        {
            return new Pkcs12SafeBag(new SafeBag(bagType, bagValue.ToAsn1Object(), new DerSet(bagAttrs)));
        }
    }
}
