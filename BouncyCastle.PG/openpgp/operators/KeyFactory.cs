using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class KeyFactory
    {
        public static IAsymmetricPrivateKey ConvertPrivate(PgpPrivateKey privateKey)
        {
            return null;
        }

        public static IAsymmetricPublicKey ConvertPublic(PgpPublicKey publicKey)
        {
            PublicKeyPacket publicPk = publicKey.PublicKeyPacket;

            switch (publicKey.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    RsaPublicBcpgKey rsaK = (RsaPublicBcpgKey)publicPk.Key;
  
                    return new AsymmetricRsaPublicKey(FipsRsa.Alg, rsaK.Modulus, rsaK.PublicExponent);
                case PublicKeyAlgorithmTag.Dsa:
                    DsaPublicBcpgKey dsaK = (DsaPublicBcpgKey)publicPk.Key;
  
                    return new AsymmetricDsaPublicKey(FipsDsa.Alg, new DsaDomainParameters(dsaK.P, dsaK.Q, dsaK.G), dsaK.Y);
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPublicBcpgKey elK = (ElGamalPublicBcpgKey)publicPk.Key;

                    return new AsymmetricDHPublicKey(FipsDsa.Alg, new DHDomainParameters(elK.P, elK.G), elK.Y);
                default:
                    throw new PgpException("unknown public key algorithm encountered");
            }
        }
    }
}
