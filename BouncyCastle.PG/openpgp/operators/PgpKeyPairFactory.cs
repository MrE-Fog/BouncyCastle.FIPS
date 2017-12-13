using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Asymmetric;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpKeyPairFactory
    {
        private AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> kp;
        private DateTime now;
        private PublicKeyAlgorithmTag algorithmTag;

        public static PgpKeyPair Convert(PublicKeyAlgorithmTag algorithmTag, AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> kp, DateTime date)
        {
            PublicKeyPacket pubPacket = new PublicKeyPacket(algorithmTag, date, new RsaPublicBcpgKey(kp.PublicKey.Modulus, kp.PublicKey.PublicExponent));

            PgpPublicKey pubKey = new PgpPublicKey(pubPacket, new PgpKeyFingerprintCalculator());
            PgpPrivateKey privKey = new PgpPrivateKey(pubKey.KeyId, pubPacket, new RsaSecretBcpgKey(kp.PrivateKey.PrivateExponent, kp.PrivateKey.P, kp.PrivateKey.Q));

            return new PgpKeyPair(pubKey, privKey);
        }
    }
}
