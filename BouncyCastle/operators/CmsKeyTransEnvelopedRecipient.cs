
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class CmsKeyTransEnvelopedRecipient : IKeyTransRecipient
    {
        private readonly IAsymmetricPrivateKey privKey;

        private SecureRandom random;

        /// <summary>
        /// Base constructor - just the private key.
        /// </summary>
        /// <param name="privKey">The private key to use.</param>
        public CmsKeyTransEnvelopedRecipient(IAsymmetricPrivateKey privKey): this(privKey, null)
        {
        }

        /// <summary>
        /// Constructor with a random source for blinding operations on the private key.
        /// </summary>
        /// <param name="privKey">The private key to use.</param>
        /// <param name="random">A source of randomness.</param>
        public CmsKeyTransEnvelopedRecipient(IAsymmetricPrivateKey privKey, SecureRandom random)
        {
            this.privKey = privKey;
            this.random = random;
        }

        public RecipientOperator GetRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
        {
            byte[] keyBytes = null;
            AsymmetricRsaPrivateKey rsaKey = privKey as AsymmetricRsaPrivateKey;
  
            if (rsaKey != null)
            {
                // random required for blinding operations
                keyBytes = CryptoServicesRegistrar.CreateService(rsaKey, random != null ? random: CryptoServicesRegistrar.GetSecureRandom()).CreateKeyUnwrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha1)).Unwrap(encryptedContentKey, 0, encryptedContentKey.Length).Collect();
            }
            IParameters<Algorithm> cipherParams = Utils.GetCipherParameters(contentEncryptionAlgorithm);

            ICipherBuilder<AlgorithmIdentifier>  decryptor;

            if (Utils.IsBlockMode(cipherParams.Algorithm))
            {
                decryptor = new PkixBlockCipherBuilder(contentEncryptionAlgorithm, Utils.CreateBlockDecryptorBuilder(contentEncryptionAlgorithm, keyBytes, cipherParams));
            }
            else if (Utils.IsAeadMode(cipherParams.Algorithm))
            {
                decryptor = new PkixAeadCipherBuilder(contentEncryptionAlgorithm, Utils.CreateAeadDecryptorBuilder(contentEncryptionAlgorithm, keyBytes, cipherParams));
            }
            else
            {
                decryptor = new PkixCipherBuilder(contentEncryptionAlgorithm, Utils.CreateDecryptorBuilder(contentEncryptionAlgorithm, keyBytes, cipherParams));
            }

            return new RecipientOperator(decryptor);
        }
    }
}
