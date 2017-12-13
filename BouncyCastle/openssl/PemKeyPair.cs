using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.OpenSsl
{ 
    public class PemKeyPair
    {
        private readonly SubjectPublicKeyInfo mPublicKeyInfo;
        private readonly PrivateKeyInfo mPrivateKeyInfo;

        public PemKeyPair(SubjectPublicKeyInfo publicKeyInfo, PrivateKeyInfo privateKeyInfo)
        {
            this.mPublicKeyInfo = publicKeyInfo;
            this.mPrivateKeyInfo = privateKeyInfo;
        }

        public PrivateKeyInfo PrivateKeyInfo
        {
            get
            {
                return mPrivateKeyInfo;
            }
        }

        public SubjectPublicKeyInfo PublicKeyInfo
        {
            get
            {
                return mPublicKeyInfo;
            }
        }
    }
}
