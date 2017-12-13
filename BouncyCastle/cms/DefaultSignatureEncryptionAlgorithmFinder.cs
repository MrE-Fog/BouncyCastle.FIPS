using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    public class DefaultSignatureEncryptionAlgorithmFinder : ISignatureEncryptionAlgorithmFinder
    {
        private static readonly ISet Rsa_Pkcs1d5 = new HashSet();

        static DefaultSignatureEncryptionAlgorithmFinder()
        {
            Rsa_Pkcs1d5.Add(PkcsObjectIdentifiers.MD2WithRsaEncryption);
            Rsa_Pkcs1d5.Add(PkcsObjectIdentifiers.MD4WithRsaEncryption);
            Rsa_Pkcs1d5.Add(PkcsObjectIdentifiers.MD5WithRsaEncryption);
            Rsa_Pkcs1d5.Add(PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            Rsa_Pkcs1d5.Add(OiwObjectIdentifiers.MD4WithRsaEncryption);
            Rsa_Pkcs1d5.Add(OiwObjectIdentifiers.MD4WithRsa);
            Rsa_Pkcs1d5.Add(OiwObjectIdentifiers.MD5WithRsa);
            Rsa_Pkcs1d5.Add(OiwObjectIdentifiers.Sha1WithRsa);
            Rsa_Pkcs1d5.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            Rsa_Pkcs1d5.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            Rsa_Pkcs1d5.Add(TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
        }

        public AlgorithmIdentifier FindEncryptionAlgorithm(AlgorithmIdentifier signatureAlgorithm)
        {
            // RFC3370 section 3.2 with RFC 5754 update
            if (Rsa_Pkcs1d5.Contains(signatureAlgorithm.Algorithm))
            {
                return new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            }

            return signatureAlgorithm;
        }
    }
}
