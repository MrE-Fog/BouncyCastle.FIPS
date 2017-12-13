using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Operators
{
    public class PkixPbeEncryptorBuilder
    {
        private DerObjectIdentifier algorithm;
        private DerObjectIdentifier keyEncAlgorithm;
        private PasswordConverter converter;
        private DigestAlgorithm digestAlgorithm;

        private SecureRandom random = null;
        private byte[] salt = new byte[0];
        private int iterationCount = 1024;

        private ICipherBuilder<IParameters<Algorithm>> cipherBuilder;

        /// <summary>
        /// Basic constructor - UTF8 conversion with HMAC SHA-384 as the PRF, unless the algorithm specifies otherwise.
        /// </summary>
        /// <param name="keyEncAlgorithm"></param>
        public PkixPbeEncryptorBuilder(DerObjectIdentifier keyEncAlgorithm) : this(PasswordConverter.UTF8, FipsShs.Sha384HMac, keyEncAlgorithm)
        {
        }

        public PkixPbeEncryptorBuilder(PasswordConverter converter, DigestAlgorithm digestAlgorithm, DerObjectIdentifier keyEncAlgorithm)
        {
            if (keyEncAlgorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc)
                || keyEncAlgorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc))
            {
                this.algorithm = keyEncAlgorithm;
                this.keyEncAlgorithm = keyEncAlgorithm;
                this.converter = PasswordConverter.PKCS12;
                this.digestAlgorithm = FipsShs.Sha1;
            }
            else
            {
                this.algorithm = PkcsObjectIdentifiers.IdPbeS2;
                this.keyEncAlgorithm = keyEncAlgorithm;
                this.converter = converter;
                this.digestAlgorithm = digestAlgorithm;
            }
        }

        public PkixPbeEncryptorBuilder WithSalt(byte[] salt)
        {
            this.salt = Arrays.Clone(salt);

            return this;
        }

        public PkixPbeEncryptorBuilder WithIterationCount(int iterationCount)
        {
            this.iterationCount = iterationCount;

            return this;
        }

        public PkixPbeEncryptorBuilder WithSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        public ICipherBuilder<AlgorithmIdentifier> Build(char[] password)
        {
            if (algorithm.Equals(PkcsObjectIdentifiers.IdPbeS2))
            {
                IPasswordBasedDeriverBuilder<FipsPbkd.Parameters> pbeDeriverBuilder = CryptoServicesRegistrar.CreateService(FipsPbkd.PbkdF2).From(converter, password);

                IPasswordBasedDeriver<FipsPbkd.Parameters> pbeDeriver = pbeDeriverBuilder
                                                                    .WithPrf(digestAlgorithm)
                                                                    .WithSalt(salt)
                                                                    .WithIterationCount(iterationCount)
                                                                    .Build();

                byte[] keyEnc = pbeDeriver.DeriveKey(TargetKeyType.CIPHER, (int)Utils.keySizesInBytes[keyEncAlgorithm]);

                EncryptionScheme encScheme = Utils.GetEncryptionSchemeIdentifier(keyEncAlgorithm, random);

                PbeS2Parameters algParams = new PbeS2Parameters(
                   new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2, new Pbkdf2Params(salt, iterationCount,
                       new AlgorithmIdentifier((DerObjectIdentifier)Utils.digestTable[digestAlgorithm], DerNull.Instance))),
                   encScheme);


                IParameters<Algorithm> cipherParams = Utils.GetCipherParameters(encScheme);

                if (Utils.IsBlockMode(cipherParams.Algorithm))
                {
                    return new PbeBlockCipherBuilder(new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, algParams), Utils.CreateBlockEncryptorBuilder(keyEncAlgorithm, keyEnc, cipherParams));
                }
                else if (Utils.IsAeadMode(cipherParams.Algorithm))
                {
                    return new PkixAeadCipherBuilder(new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, algParams), Utils.CreateAeadEncryptorBuilder(keyEncAlgorithm, keyEnc, cipherParams));
                }
                else
                {
                    return new PkixCipherBuilder(new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, algParams), Utils.CreateEncryptorBuilder(keyEncAlgorithm, keyEnc, cipherParams));
                }
            }
            else if (algorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc)
                  || algorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc))
            {
                int keySize = algorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc) ? 16 : 24;
                Pkcs12PbeParams pbeParams = new Pkcs12PbeParams(salt, iterationCount);
                // we ignore converter as it's specified by the algorithm
                IPasswordBasedDeriverBuilder<Pbkd.PbkdParameters> pbeDeriverBuilder = CryptoServicesRegistrar.CreateService(Pbkd.Pkcs12).From(PasswordConverter.PKCS12, password);

                IPasswordBasedDeriver<Pbkd.PbkdParameters> pbeDeriver = pbeDeriverBuilder
                                                .WithPrf(FipsShs.Sha1)
                                                .WithSalt(pbeParams.GetIV())
                                                .WithIterationCount(pbeParams.Iterations.IntValue)
                                                .Build();

                byte[][] keyIV = pbeDeriver.DeriveKeyAndIV(TargetKeyType.CIPHER, keySize, 8);
                AlgorithmIdentifier algDetails = new AlgorithmIdentifier(algorithm, pbeParams);
            
                return new PbeBlockCipherBuilder(algDetails, Utils.CreateBlockEncryptorBuilder(algDetails, keyIV[0], keyIV[1]));
            }

            throw new InvalidOperationException("cannot match algorithm: " + algorithm);
        }

        private class PbeBlockCipherBuilder : ICipherBuilder<AlgorithmIdentifier>
        {
            private readonly AlgorithmIdentifier algDetails;
            private readonly IBlockCipherBuilder<IParameters<Algorithm>> baseBlockCipherBuilder;

            internal PbeBlockCipherBuilder(AlgorithmIdentifier algDetails, IBlockCipherBuilder<IParameters<Algorithm>> baseCipherBuilder)
            {
                this.algDetails = algDetails;
                this.baseBlockCipherBuilder = baseCipherBuilder;
            }

            public AlgorithmIdentifier AlgorithmDetails
            {
                get
                {
                    return algDetails;
                }
            }

            public int GetMaxOutputSize(int inputLen)
            {
                int blockSize = baseBlockCipherBuilder.BlockSize;

                if (inputLen % blockSize == 0)
                {
                    // allow for padding
                    baseBlockCipherBuilder.GetMaxOutputSize(inputLen + blockSize);
                }

                return baseBlockCipherBuilder.GetMaxOutputSize(((inputLen + blockSize - 1) / blockSize) * blockSize);
            }

            public ICipher BuildCipher(Stream stream)
            {
                return baseBlockCipherBuilder.BuildPaddedCipher(stream, new Pkcs7Padding());
            }
        }
    }
}
