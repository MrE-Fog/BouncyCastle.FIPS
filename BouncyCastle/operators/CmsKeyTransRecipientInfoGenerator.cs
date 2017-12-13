using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Cms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Operators
{
    public class CmsKeyTransRecipientInfoGenerator: KeyTransRecipientInfoGenerator
    {
        private IAsymmetricPublicKey asymmetricPublicKey;
        private AlgorithmIdentifier wrapAlgID;
        private IParameters<Algorithm> wrapParams;

        public CmsKeyTransRecipientInfoGenerator(X509Certificate recipCert, AlgorithmIdentifier wrappingAlgID): base(new Asn1.Cms.IssuerAndSerialNumber(recipCert.IssuerDN, new DerInteger(recipCert.SerialNumber)))
        {
            this.wrapAlgID = wrappingAlgID;
            this.wrapParams = FipsRsa.WrapOaep;
            this.asymmetricPublicKey = recipCert.GetPublicKey();
        }

        public CmsKeyTransRecipientInfoGenerator(X509Certificate recipCert, IParameters<Algorithm> wrapParameters) : base(new Asn1.Cms.IssuerAndSerialNumber(recipCert.IssuerDN, new DerInteger(recipCert.SerialNumber)))
        {
            this.wrapAlgID = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsaesOaep, new RsaesOaepParameters());
            this.wrapParams = FipsRsa.WrapOaep;
            this.asymmetricPublicKey = recipCert.GetPublicKey();
        }

        public CmsKeyTransRecipientInfoGenerator(byte[] subjectKeyID, AlgorithmIdentifier wrappingAlgID, IAsymmetricPublicKey asymmetricPublicKey) : base(subjectKeyID)
        {
            this.wrapAlgID = wrappingAlgID;
            this.wrapParams = FipsRsa.WrapOaep;
            this.asymmetricPublicKey = asymmetricPublicKey;
        }

        public CmsKeyTransRecipientInfoGenerator(byte[] subjectKeyID, IParameters<Algorithm> wrapParameters, IAsymmetricPublicKey asymmetricPublicKey): base(subjectKeyID)
        {
            this.wrapAlgID = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsaesOaep, new RsaesOaepParameters());
            this.wrapParams = FipsRsa.WrapOaep;
            this.asymmetricPublicKey = asymmetricPublicKey;
        }

        protected override AlgorithmIdentifier AlgorithmDetails
        {
            get
            {
                return wrapAlgID;
            }
        }

        protected override byte[] GenerateWrappedKey(ISymmetricKey contentKey)
        {
            AsymmetricRsaPublicKey rsaKey = asymmetricPublicKey as AsymmetricRsaPublicKey;
            if (rsaKey != null)
            {
                IKeyWrapper<FipsRsa.OaepWrapParameters> wrapper = CryptoServicesRegistrar.CreateService(rsaKey, new Security.SecureRandom()).CreateKeyWrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha1));

                byte[] encKey = wrapper.Wrap(contentKey.GetKeyBytes()).Collect();
  
                return encKey;
            }

            throw new InvalidOperationException("algorithm for public key not matched");
        }
    }
}
