using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using System;

namespace Org.BouncyCastle.Security
{
    public class AsymmetricKeyFactory
    {
        private AsymmetricKeyFactory()
        {
        }

        public static IAsymmetricPublicKey CreatePublicKey(byte[] encodedPublicKeyInfo)
        {
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.GetInstance(encodedPublicKeyInfo);
            AlgorithmIdentifier algId = keyInfo.AlgorithmID;

            if (algId.Algorithm.Equals(PkcsObjectIdentifiers.RsaEncryption)
                || algId.Algorithm.Equals(X509ObjectIdentifiers.IdEARsa))
            {
                return new AsymmetricRsaPublicKey(FipsRsa.Alg, encodedPublicKeyInfo);
            }
            else if (algId.Algorithm.Equals(X9ObjectIdentifiers.IdDsa)
                || algId.Algorithm.Equals(OiwObjectIdentifiers.DsaWithSha1))
            {
                return new AsymmetricDsaPublicKey(FipsDsa.Alg, encodedPublicKeyInfo);
            }
            else if (algId.Algorithm.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                return new AsymmetricECPublicKey(FipsEC.Alg, encodedPublicKeyInfo);
            }
            else if (algId.Algorithm.Equals(BCObjectIdentifiers.sphincs256))
            {
                return new AsymmetricSphincsPublicKey(Sphincs.Alg, encodedPublicKeyInfo);
            }
            else if (algId.Algorithm.Equals(BCObjectIdentifiers.newHope))
            {
                return new AsymmetricNHPublicKey(NewHope.Alg, encodedPublicKeyInfo);
            }
            else if (algId.Algorithm.Equals(X9ObjectIdentifiers.DHPublicNumber)
                || algId.Algorithm.Equals(PkcsObjectIdentifiers.DhKeyAgreement))
            {
                return new AsymmetricDHPublicKey(new GeneralAlgorithm("DH"), encodedPublicKeyInfo);
            }
            else if (algId.Algorithm.Equals(OiwObjectIdentifiers.ElGamalAlgorithm))
            {
                return new AsymmetricDHPublicKey(ElGamal.Alg, encodedPublicKeyInfo);
            }
            else
            {
                throw new ArgumentException("algorithm identifier in key not recognised");
            }
        }

        public static IAsymmetricPrivateKey CreatePrivateKey(byte[] encodedPrivateKeyInfo)
        {
            PrivateKeyInfo keyInfo = PrivateKeyInfo.GetInstance(encodedPrivateKeyInfo);
            AlgorithmIdentifier algId = keyInfo.PrivateKeyAlgorithm;

            if (algId.Algorithm.Equals(PkcsObjectIdentifiers.RsaEncryption)
                || algId.Algorithm.Equals(X509ObjectIdentifiers.IdEARsa))
            {
                return new AsymmetricRsaPrivateKey(FipsRsa.Alg, encodedPrivateKeyInfo);
            }
            else if (algId.Algorithm.Equals(X9ObjectIdentifiers.IdDsa)
                || algId.Algorithm.Equals(OiwObjectIdentifiers.DsaWithSha1))
            {
                return new AsymmetricDsaPrivateKey(FipsDsa.Alg, encodedPrivateKeyInfo);
            }
            else if (algId.Algorithm.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                return new AsymmetricECPrivateKey(FipsEC.Alg, encodedPrivateKeyInfo);
            }
            else if (algId.Algorithm.Equals(BCObjectIdentifiers.sphincs256))
            {
                return new AsymmetricSphincsPrivateKey(Sphincs.Alg, encodedPrivateKeyInfo);
            }
            else if (algId.Algorithm.Equals(BCObjectIdentifiers.newHope))
            {
                return new AsymmetricNHPrivateKey(NewHope.Alg, encodedPrivateKeyInfo);
            }
            else if (algId.Algorithm.Equals(X9ObjectIdentifiers.DHPublicNumber)
                || algId.Algorithm.Equals(PkcsObjectIdentifiers.DhKeyAgreement))
            {
                return new AsymmetricDHPrivateKey(new GeneralAlgorithm("DH"), encodedPrivateKeyInfo);
            }
            else if (algId.Algorithm.Equals(OiwObjectIdentifiers.ElGamalAlgorithm))
            {
                return new AsymmetricDHPrivateKey(ElGamal.Alg, encodedPrivateKeyInfo);
            }
            else
            {
                throw new ArgumentException("algorithm identifier in key not recognised");
            }
        }
    }
}
