using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpPbeSecretKeyEncryptorBuilder
    {
        private readonly SymmetricKeyAlgorithmTag encAlgorithm;

        private int s2kCount = 0x60;
        private IDigestFactory<PgpDigestTypeIdentifier> s2kDigestFactory = new PgpSha1DigestFactory();
        private int checksumUsage = SecretKeyPacket.UsageSha1;

        private SecureRandom random;

        public PgpPbeSecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTag encAlgorithm)
        {
            this.encAlgorithm = encAlgorithm;
        }

        public PgpPbeSecretKeyEncryptorBuilder WithS2kDigestFactory(IDigestFactory<PgpDigestTypeIdentifier> s2kDigestFactory)
        {
            this.s2kDigestFactory = s2kDigestFactory;

            return this;
        }

        public PgpPbeSecretKeyEncryptorBuilder WithS2kCount(int s2kCount)
        {
            if (s2kCount < 0 || s2kCount > 0xff)
            {
                throw new ArgumentException("s2kCount value outside of range 0 to 255.");
            }

            this.s2kCount = s2kCount;

            return this;
        }

        public PgpPbeSecretKeyEncryptorBuilder WithChecksumUsage(int checksumUsage)
        {
            this.checksumUsage = checksumUsage;

            return this;
        }

        public PgpPbeSecretKeyEncryptorBuilder WithSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        public IPbeSecretKeyEncryptor Build(char[] passPhrase)
        {
            byte[] s2kIv = new byte[8];

            if (random == null)
            {
                random = CryptoServicesRegistrar.GetSecureRandom();
            }

            random.NextBytes(s2kIv);

            S2k s2k = new S2k(s2kDigestFactory.AlgorithmDetails.Algorithm, s2kIv, s2kCount);

            byte[] key = PgpUtilities.MakeKeyFromPassPhrase(s2kDigestFactory, encAlgorithm, s2k, passPhrase);

            return new SecretKeyEncryptor(encAlgorithm, key, null, s2k, new PgpSha1DigestFactory());
        }

        private class SecretKeyEncryptor : IPbeSecretKeyEncryptor
        {
            private readonly byte[] iv;
            private readonly SymmetricKeyAlgorithmTag symAlg;
            private readonly byte[] key;
            private readonly S2k s2k;
            private readonly IDigestFactory<PgpDigestTypeIdentifier> mChecksumCalculatorFactory;

            private SecureRandom random;
            private ICipherBuilder<FipsTripleDes.ParametersWithIV> cipherBuilder;

            internal SecretKeyEncryptor(SymmetricKeyAlgorithmTag symAlg, byte[] key, byte[] iv, S2k s2k, IDigestFactory<PgpDigestTypeIdentifier> checksumCalculatorFactory)
            {
                FipsTripleDes.ParametersWithIV parameters;
                if (iv != null)
                {
                    parameters = FipsTripleDes.Cfb64.WithIV(iv);
                    this.iv = iv;     
                }
                else
                {
                    if (this.random == null)
                    {
                        this.random = new SecureRandom();
                    }

                    parameters = FipsTripleDes.Cfb64.WithIV(random);

                    this.iv = parameters.GetIV();
                }
                this.s2k = s2k;

                cipherBuilder = CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(key)).CreateEncryptorBuilder(FipsTripleDes.Cfb64.WithIV(iv));
            }

            public PgpPbeKeyEncryptionParameters AlgorithmDetails
            {
                get
                {
                    return new PgpPbeKeyEncryptionParameters(symAlg, s2k, iv);
                }
            }

            public IDigestFactory<PgpDigestTypeIdentifier> ChecksumCalculatorFactory
            {
                get
                {
                    return mChecksumCalculatorFactory;
                }
            }

            public IPbeSecretKeyEncryptor WithIV(byte[] newIV)
            {
                return new SecretKeyEncryptor(symAlg, key, iv, s2k, mChecksumCalculatorFactory);
            }

            public IBlockResult Wrap(byte[] keyData)
            {
                MemoryOutputStream mOut = new MemoryOutputStream();

                ICipher keyCipher = cipherBuilder.BuildCipher(mOut);

                keyCipher.Stream.Write(keyData, 0, keyData.Length);

                keyCipher.Stream.Close();

                return new SimpleBlockResult(mOut.ToArray());
            }
        }
    }
}
