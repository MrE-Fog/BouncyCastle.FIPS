
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    /// Builder class for creating a provider of password based decryptors based on AlgorithmIdentifier objects found in 
    /// encrypted structures.
    /// </summary>
    public class PkixPbeDecryptorProviderBuilder 
    {
        private PasswordConverter converter;

        /// <summary>
        /// Base constructor.
        /// </summary>
        public PkixPbeDecryptorProviderBuilder()
        {
            this.converter = PasswordConverter.UTF8;
        }

        /// <summary>
        /// Build a provider of decryptors keyed by password.
        /// </summary>
        /// <param name="password">The password to configure the decryptor for.</param>
        /// <returns>A provider for decryptors that will be keyed by password.</returns>
        public IDecryptorBuilderProvider<AlgorithmIdentifier> Build(char[] password)
        {
            return new MyDecryptorBuilderProvider(converter, password);
        }

        private class MyDecryptorBuilderProvider : IDecryptorBuilderProvider<AlgorithmIdentifier>
        {
            private PasswordConverter converter;
            private readonly char[] password;

            internal MyDecryptorBuilderProvider(PasswordConverter converter, char[] password)
            {
                this.converter = converter;
                this.password = password;
            }

            public ICipherBuilder<AlgorithmIdentifier> CreateDecryptorBuilder(AlgorithmIdentifier algorithmDetails)
            {
                if (algorithmDetails.Algorithm.Equals(PkcsObjectIdentifiers.IdPbeS2))
                {
                    IPasswordBasedDeriverBuilder<FipsPbkd.Parameters> pbeDeriverBuilder = CryptoServicesRegistrar.CreateService(FipsPbkd.PbkdF2).From(converter.Convert(password));
                    PbeS2Parameters pbeParams = PbeS2Parameters.GetInstance(algorithmDetails.Parameters);
                    Pbkdf2Params pbkdfParams = Pbkdf2Params.GetInstance(pbeParams.KeyDerivationFunc.Parameters);
                    AlgorithmIdentifier encScheme = pbeParams.EncryptionScheme;
                    IPasswordBasedDeriver<FipsPbkd.Parameters> pbeDeriver = pbeDeriverBuilder
                                                                        .WithPrf((DigestAlgorithm)Utils.digestTable[pbkdfParams.Prf.Algorithm])
                                                                        .WithSalt(pbkdfParams.GetSalt())
                                                                        .WithIterationCount(pbkdfParams.IterationCount.IntValue)
                                                                        .Build();

                    byte[] keyEnc = pbeDeriver.DeriveKey(TargetKeyType.CIPHER, (pbkdfParams.KeyLength != null ? pbkdfParams.KeyLength.IntValue : (int)Utils.keySizesInBytes[encScheme.Algorithm]));
                    IParameters<Algorithm> cipherParams = Utils.GetCipherParameters(encScheme);

                    if (Utils.IsBlockMode(cipherParams.Algorithm))
                    {
                        return new PbeBlockCipherBuilder(algorithmDetails, Utils.CreateBlockDecryptorBuilder(encScheme, keyEnc, cipherParams));
                    }
                    else if (Utils.IsAeadMode(cipherParams.Algorithm))
                    {
                        return new PkixAeadCipherBuilder(algorithmDetails, Utils.CreateAeadDecryptorBuilder(encScheme, keyEnc, cipherParams));
                    }
                    else
                    {
                        return new PkixCipherBuilder(algorithmDetails, Utils.CreateDecryptorBuilder(encScheme, keyEnc, cipherParams));
                    }
                }
                else if (algorithmDetails.Algorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc)
                      || algorithmDetails.Algorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc))
                {
                    int keySize = algorithmDetails.Algorithm.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc) ? 16 : 24;
                    Pkcs12PbeParams pbeParams = Pkcs12PbeParams.GetInstance(algorithmDetails.Parameters);
                    // we ignore converter as it's specified by the algorithm
                    IPasswordBasedDeriverBuilder<Pbkd.PbkdParameters> pbeDeriverBuilder = CryptoServicesRegistrar.CreateService(Pbkd.Pkcs12).From(PasswordConverter.PKCS12, password);

                    IPasswordBasedDeriver<Pbkd.PbkdParameters> pbeDeriver = pbeDeriverBuilder
                                                    .WithPrf(FipsShs.Sha1)
                                                    .WithSalt(pbeParams.GetIV())
                                                    .WithIterationCount(pbeParams.Iterations.IntValue)
                                                    .Build();
                    
                    byte[][] keyIV = pbeDeriver.DeriveKeyAndIV(TargetKeyType.CIPHER, keySize, 8);

                    return new PbeBlockCipherBuilder(algorithmDetails, Utils.CreateDecryptorBuilder(algorithmDetails, keyIV[0], keyIV[1]));
                }

                throw new InvalidOperationException("cannot match algorithm: " + algorithmDetails.Algorithm);
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
}
