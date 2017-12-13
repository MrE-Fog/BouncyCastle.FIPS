using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Nist;

namespace Org.BouncyCastle.Operators
{
    public class PkixContentEncryptor: ICipherBuilderWithKey<AlgorithmIdentifier>
    {
        private static IDictionary<DerObjectIdentifier, Func<SecureRandom, ISymmetricKey>> keyGenerators = new Dictionary<DerObjectIdentifier, Func<SecureRandom, ISymmetricKey>>();

        static PkixContentEncryptor()
        {
            keyGenerators.Add(PkcsObjectIdentifiers.DesEde3Cbc, (random) => { return CryptoServicesRegistrar.CreateGenerator(FipsTripleDes.KeyGen168, random).GenerateKey(); });
            keyGenerators.Add(NistObjectIdentifiers.IdAes128Cbc, (random) => { return CryptoServicesRegistrar.CreateGenerator(FipsAes.KeyGen128, random).GenerateKey(); });
            keyGenerators.Add(NistObjectIdentifiers.IdAes128Ccm, keyGenerators[NistObjectIdentifiers.IdAes128Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes128Cfb, keyGenerators[NistObjectIdentifiers.IdAes128Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes128Ecb, keyGenerators[NistObjectIdentifiers.IdAes128Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes128Gcm, keyGenerators[NistObjectIdentifiers.IdAes128Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes128Ofb, keyGenerators[NistObjectIdentifiers.IdAes128Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes192Cbc, (random) => { return CryptoServicesRegistrar.CreateGenerator(FipsAes.KeyGen192, random).GenerateKey(); });
            keyGenerators.Add(NistObjectIdentifiers.IdAes192Ccm, keyGenerators[NistObjectIdentifiers.IdAes192Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes192Cfb, keyGenerators[NistObjectIdentifiers.IdAes192Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes192Ecb, keyGenerators[NistObjectIdentifiers.IdAes192Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes192Gcm, keyGenerators[NistObjectIdentifiers.IdAes192Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes192Ofb, keyGenerators[NistObjectIdentifiers.IdAes192Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes256Cbc, (random) => { return CryptoServicesRegistrar.CreateGenerator(FipsAes.KeyGen256, random).GenerateKey(); });
            keyGenerators.Add(NistObjectIdentifiers.IdAes256Ccm, keyGenerators[NistObjectIdentifiers.IdAes256Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes256Cfb, keyGenerators[NistObjectIdentifiers.IdAes256Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes256Ecb, keyGenerators[NistObjectIdentifiers.IdAes256Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes256Gcm, keyGenerators[NistObjectIdentifiers.IdAes256Cbc]);
            keyGenerators.Add(NistObjectIdentifiers.IdAes256Ofb, keyGenerators[NistObjectIdentifiers.IdAes256Cbc]);
        }

        ISymmetricKey key;
        AlgorithmIdentifier algId;
        ICipherBuilder<AlgorithmIdentifier> cipherBuilder;

        public PkixContentEncryptor(DerObjectIdentifier encAlgorithm, SecureRandom random)
        {
            key = keyGenerators[encAlgorithm](random);

            algId = Utils.GetEncryptionSchemeIdentifier(encAlgorithm, random);

            IParameters<Algorithm> cipherParams = Utils.GetCipherParameters(algId);

            if (Utils.IsBlockMode(cipherParams.Algorithm))
            {
                cipherBuilder = new PkixBlockCipherBuilder(algId, Utils.CreateBlockEncryptorBuilder(encAlgorithm, key.GetKeyBytes(), cipherParams));
            }
            else if (Utils.IsAeadMode(cipherParams.Algorithm))
            {
                cipherBuilder = new PkixAeadCipherBuilder(algId, Utils.CreateAeadEncryptorBuilder(encAlgorithm, key.GetKeyBytes(), cipherParams));
            }
            else
            {
                cipherBuilder = new PkixCipherBuilder(algId, Utils.CreateEncryptorBuilder(encAlgorithm, key.GetKeyBytes(), cipherParams));
            }
        }

        public AlgorithmIdentifier AlgorithmDetails { get { return algId; } }

        public ISymmetricKey Key
        {
            get
            {
                return key;
            }
        }

        public ICipher BuildCipher(Stream stream)
        {
            return cipherBuilder.BuildCipher(stream);
        }

        public int GetMaxOutputSize(int inputLen)
        {
            return cipherBuilder.GetMaxOutputSize(inputLen);
        }
    }
}
