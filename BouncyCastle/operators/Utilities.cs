using Org.BouncyCastle.Ans1.BC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Operators
{
    internal class Utils
    {
        private static readonly Asn1Null derNull = DerNull.Instance;

        private static readonly IDictionary algorithms = Platform.CreateHashtable();
        private static readonly IDictionary exParams = Platform.CreateHashtable();
        private static readonly ISet noParams = new HashSet();
        private static readonly IDictionary rsaPkcs1Table = Platform.CreateHashtable();
        private static readonly IDictionary ecdsaTable = Platform.CreateHashtable();
        private static readonly IDictionary dsaTable = Platform.CreateHashtable();
        private static readonly IDictionary pssTable = Platform.CreateHashtable();
        private static readonly IDictionary aeadModes = Platform.CreateHashtable();

        internal static readonly IDictionary ivSizesInBytes = Platform.CreateHashtable();
        internal static readonly IDictionary digestTable = Platform.CreateHashtable();
        internal static readonly IDictionary digestSize = Platform.CreateHashtable();
        internal static readonly IDictionary keySizesInBytes = Platform.CreateHashtable();

        internal static readonly IDictionary pkcs12MacAlgIds = Platform.CreateHashtable();
        internal static readonly IDictionary pkcs12MacIds = Platform.CreateHashtable();

        private static IDictionary<DerObjectIdentifier, Func<byte[], IParameters<Algorithm>, IBlockCipherBuilder<IParameters<Algorithm>>>> blockEncryptor = new Dictionary<DerObjectIdentifier, Func<byte[], IParameters<Algorithm>, IBlockCipherBuilder<IParameters<Algorithm>>>>();
        private static IDictionary<DerObjectIdentifier, Func<byte[], IParameters<Algorithm>, IBlockCipherBuilder<IParameters<Algorithm>>>> blockDecryptor = new Dictionary<DerObjectIdentifier, Func<byte[], IParameters<Algorithm>, IBlockCipherBuilder<IParameters<Algorithm>>>>();
        private static IDictionary<DerObjectIdentifier, Func<SecureRandom, ISymmetricKey>> aeadEncryptor = new Dictionary<DerObjectIdentifier, Func<SecureRandom, ISymmetricKey>>();
        private static IDictionary<DerObjectIdentifier, Func<SecureRandom, ISymmetricKey>> aeadDecryptor = new Dictionary<DerObjectIdentifier, Func<SecureRandom, ISymmetricKey>>();

        static Utils()
        {
            algorithms.Add("SHA1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            algorithms.Add("SHA1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            algorithms.Add("SHA224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            algorithms.Add("SHA224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            algorithms.Add("SHA256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            algorithms.Add("SHA256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            algorithms.Add("SHA384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            algorithms.Add("SHA384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            algorithms.Add("SHA512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            algorithms.Add("SHA512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            algorithms.Add("SHA1WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
            algorithms.Add("DSAWITHSHA1", X9ObjectIdentifiers.IdDsaWithSha1);
            algorithms.Add("SHA224WITHDSA", NistObjectIdentifiers.DsaWithSha224);
            algorithms.Add("SHA256WITHDSA", NistObjectIdentifiers.DsaWithSha256);
            algorithms.Add("SHA384WITHDSA", NistObjectIdentifiers.DsaWithSha384);
            algorithms.Add("SHA512WITHDSA", NistObjectIdentifiers.DsaWithSha512);
            algorithms.Add("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
            algorithms.Add("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
            algorithms.Add("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
            algorithms.Add("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
            algorithms.Add("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
            algorithms.Add("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
            noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            noParams.Add(NistObjectIdentifiers.DsaWithSha224);
            noParams.Add(NistObjectIdentifiers.DsaWithSha256);
            noParams.Add(NistObjectIdentifiers.DsaWithSha384);
            noParams.Add(NistObjectIdentifiers.DsaWithSha512);

            //
            // explicit params
            //
            AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            exParams.Add("SHA1WITHRSAANDMGF1", CreatePssParams(sha1AlgId, 20));
            pssTable.Add(FipsShs.Sha1, sha1AlgId);

            AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            exParams.Add("SHA224WITHRSAANDMGF1", CreatePssParams(sha224AlgId, 28));
            pssTable.Add(FipsShs.Sha224, sha224AlgId);

            AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            exParams.Add("SHA256WITHRSAANDMGF1", CreatePssParams(sha256AlgId, 32));
            pssTable.Add(FipsShs.Sha256, sha256AlgId);

            AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            exParams.Add("SHA384WITHRSAANDMGF1", CreatePssParams(sha384AlgId, 48));
            pssTable.Add(FipsShs.Sha384, sha384AlgId);

            AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            exParams.Add("SHA512WITHRSAANDMGF1", CreatePssParams(sha512AlgId, 64));
            pssTable.Add(FipsShs.Sha512, sha512AlgId);

            rsaPkcs1Table.Add(FipsShs.Sha1, new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha1WithRsaEncryption, DerNull.Instance));
            rsaPkcs1Table.Add(FipsShs.Sha224, new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha224WithRsaEncryption, DerNull.Instance));
            rsaPkcs1Table.Add(FipsShs.Sha256, new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance));
            rsaPkcs1Table.Add(FipsShs.Sha384, new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha384WithRsaEncryption, DerNull.Instance));
            rsaPkcs1Table.Add(FipsShs.Sha512, new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha512WithRsaEncryption, DerNull.Instance));

            dsaTable.Add(FipsShs.Sha1, new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsaWithSha1));
            dsaTable.Add(FipsShs.Sha224, new AlgorithmIdentifier(NistObjectIdentifiers.DsaWithSha224));
            dsaTable.Add(FipsShs.Sha256, new AlgorithmIdentifier(NistObjectIdentifiers.DsaWithSha256));
            dsaTable.Add(FipsShs.Sha384, new AlgorithmIdentifier(NistObjectIdentifiers.DsaWithSha384));
            dsaTable.Add(FipsShs.Sha512, new AlgorithmIdentifier(NistObjectIdentifiers.DsaWithSha512));

            ecdsaTable.Add(FipsShs.Sha1, new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha1));
            ecdsaTable.Add(FipsShs.Sha224, new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha224));
            ecdsaTable.Add(FipsShs.Sha256, new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256));
            ecdsaTable.Add(FipsShs.Sha384, new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha384));
            ecdsaTable.Add(FipsShs.Sha512, new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512));

            digestTable.Add(FipsShs.Sha512_256, NistObjectIdentifiers.IdSha512_256);
            digestTable.Add(FipsShs.Sha3_256, NistObjectIdentifiers.IdSha3_256);
            digestTable.Add(FipsShs.Sha1HMac, PkcsObjectIdentifiers.IdHmacWithSha1);
            digestTable.Add(FipsShs.Sha224HMac, PkcsObjectIdentifiers.IdHmacWithSha224);
            digestTable.Add(FipsShs.Sha256HMac, PkcsObjectIdentifiers.IdHmacWithSha256);
            digestTable.Add(FipsShs.Sha384HMac, PkcsObjectIdentifiers.IdHmacWithSha384);
            digestTable.Add(FipsShs.Sha512HMac, PkcsObjectIdentifiers.IdHmacWithSha512);

            digestTable.Add(OiwObjectIdentifiers.IdSha1, FipsShs.Sha1);
            digestTable.Add(NistObjectIdentifiers.IdSha224, FipsShs.Sha224);
            digestTable.Add(NistObjectIdentifiers.IdSha256, FipsShs.Sha256);
            digestTable.Add(NistObjectIdentifiers.IdSha384, FipsShs.Sha384);
            digestTable.Add(NistObjectIdentifiers.IdSha512, FipsShs.Sha512);
            digestTable.Add(NistObjectIdentifiers.IdSha512_224, FipsShs.Sha512_224);
            digestTable.Add(NistObjectIdentifiers.IdSha512_256, FipsShs.Sha512_256);

            digestTable.Add(PkcsObjectIdentifiers.IdHmacWithSha1, FipsShs.Sha1HMac);
            digestTable.Add(PkcsObjectIdentifiers.IdHmacWithSha224, FipsShs.Sha224HMac);
            digestTable.Add(PkcsObjectIdentifiers.IdHmacWithSha256, FipsShs.Sha256HMac);
            digestTable.Add(PkcsObjectIdentifiers.IdHmacWithSha384, FipsShs.Sha384HMac);
            digestTable.Add(PkcsObjectIdentifiers.IdHmacWithSha512, FipsShs.Sha512HMac);

            digestSize.Add(FipsShs.Sha1, 20);
            digestSize.Add(FipsShs.Sha224, 28);
            digestSize.Add(FipsShs.Sha256, 32);
            digestSize.Add(FipsShs.Sha384, 48);
            digestSize.Add(FipsShs.Sha512, 64);

            pkcs12MacAlgIds.Add(FipsShs.Sha1, new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance));
            pkcs12MacAlgIds.Add(FipsShs.Sha224, new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance));
            pkcs12MacAlgIds.Add(FipsShs.Sha256, new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance));
            pkcs12MacAlgIds.Add(FipsShs.Sha384, new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance));
            pkcs12MacAlgIds.Add(FipsShs.Sha512, new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance));
            pkcs12MacAlgIds.Add(FipsShs.Sha512_224, new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512_224, DerNull.Instance));
            pkcs12MacAlgIds.Add(FipsShs.Sha512_256, new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512_256, DerNull.Instance));

            pkcs12MacIds.Add(FipsShs.Sha1, FipsShs.Sha1HMac);
            pkcs12MacIds.Add(FipsShs.Sha224, FipsShs.Sha224HMac);
            pkcs12MacIds.Add(FipsShs.Sha256, FipsShs.Sha256HMac);
            pkcs12MacIds.Add(FipsShs.Sha384, FipsShs.Sha384HMac);
            pkcs12MacIds.Add(FipsShs.Sha512, FipsShs.Sha512HMac);
            pkcs12MacIds.Add(FipsShs.Sha512_224, FipsShs.Sha512_224HMac);
            pkcs12MacIds.Add(FipsShs.Sha512_256, FipsShs.Sha512_256HMac);

            keySizesInBytes.Add(NistObjectIdentifiers.IdAes128Ecb, 16);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes192Ecb, 24);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes256Ecb, 32);

            keySizesInBytes.Add(NistObjectIdentifiers.IdAes128Cbc, 16);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes192Cbc, 24);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes256Cbc, 32);

            keySizesInBytes.Add(NistObjectIdentifiers.IdAes128Cfb, 16);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes192Cfb, 24);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes256Cfb, 32);

            keySizesInBytes.Add(NistObjectIdentifiers.IdAes128Ofb, 16);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes192Ofb, 24);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes256Ofb, 32);

            keySizesInBytes.Add(NistObjectIdentifiers.IdAes128Ccm, 16);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes192Ccm, 24);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes256Ccm, 32);

            keySizesInBytes.Add(NistObjectIdentifiers.IdAes128Gcm, 16);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes192Gcm, 24);
            keySizesInBytes.Add(NistObjectIdentifiers.IdAes256Gcm, 32);

            keySizesInBytes.Add(PkcsObjectIdentifiers.DesEde3Cbc, 24);

            keySizesInBytes.Add(NttObjectIdentifiers.IdCamellia128Cbc, 16);
            keySizesInBytes.Add(NttObjectIdentifiers.IdCamellia192Cbc, 24);
            keySizesInBytes.Add(NttObjectIdentifiers.IdCamellia256Cbc, 32);

            keySizesInBytes.Add(KisaObjectIdentifiers.IdSeedCbc, 16);

            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes128Ecb, 0);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes192Ecb, 0);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes256Ecb, 0);

            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes128Cbc, 16);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes192Cbc, 16);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes256Cbc, 16);

            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes128Cfb, 16);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes192Cfb, 16);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes256Cfb, 16);

            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes128Ofb, 16);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes192Ofb, 16);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes256Ofb, 16);

            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes128Ccm, 12);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes192Ccm, 12);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes256Ccm, 12);

            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes128Gcm, 12);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes192Gcm, 12);
            ivSizesInBytes.Add(NistObjectIdentifiers.IdAes256Gcm, 12);

            ivSizesInBytes.Add(PkcsObjectIdentifiers.DesEde3Cbc, 8);

            ivSizesInBytes.Add(KisaObjectIdentifiers.IdSeedCbc, 16);

            aeadModes.Add(NistObjectIdentifiers.IdAes128Ccm, true);
            aeadModes.Add(NistObjectIdentifiers.IdAes192Ccm, true);
            aeadModes.Add(NistObjectIdentifiers.IdAes256Ccm, true);
            aeadModes.Add(NistObjectIdentifiers.IdAes128Gcm, true);
            aeadModes.Add(NistObjectIdentifiers.IdAes192Gcm, true);
            aeadModes.Add(NistObjectIdentifiers.IdAes256Gcm, true);

            blockDecryptor.Add(PkcsObjectIdentifiers.DesEde3Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(key)).CreateBlockDecryptorBuilder((FipsTripleDes.ParametersWithIV)cipherParams); });

            blockDecryptor.Add(NistObjectIdentifiers.IdAes128Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockDecryptorBuilder((FipsAes.ParametersWithIV)cipherParams); });
            blockDecryptor.Add(NistObjectIdentifiers.IdAes128Ecb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockDecryptorBuilder((FipsAes.Parameters)cipherParams); });
            blockDecryptor.Add(NistObjectIdentifiers.IdAes192Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockDecryptorBuilder((FipsAes.ParametersWithIV)cipherParams); });
            blockDecryptor.Add(NistObjectIdentifiers.IdAes192Ecb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockDecryptorBuilder((FipsAes.Parameters)cipherParams); });
            blockDecryptor.Add(NistObjectIdentifiers.IdAes256Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockDecryptorBuilder((FipsAes.ParametersWithIV)cipherParams); });
            blockDecryptor.Add(NistObjectIdentifiers.IdAes256Ecb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockDecryptorBuilder((FipsAes.Parameters)cipherParams); });

            blockDecryptor.Add(NttObjectIdentifiers.IdCamellia128Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Camellia.Key(key)).CreateBlockDecryptorBuilder((Camellia.ParametersWithIV)cipherParams); });
            blockDecryptor.Add(NttObjectIdentifiers.IdCamellia192Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Camellia.Key(key)).CreateBlockDecryptorBuilder((Camellia.ParametersWithIV)cipherParams); });
            blockDecryptor.Add(NttObjectIdentifiers.IdCamellia256Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Camellia.Key(key)).CreateBlockDecryptorBuilder((Camellia.ParametersWithIV)cipherParams); });

            blockDecryptor.Add(KisaObjectIdentifiers.IdSeedCbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Seed.Key(key)).CreateBlockDecryptorBuilder((Seed.ParametersWithIV)cipherParams); });

            blockEncryptor.Add(PkcsObjectIdentifiers.DesEde3Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(key)).CreateBlockEncryptorBuilder((FipsTripleDes.ParametersWithIV)cipherParams); });

            blockEncryptor.Add(NistObjectIdentifiers.IdAes128Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.ParametersWithIV)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes128Ecb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes192Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.ParametersWithIV)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes192Ecb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes256Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.ParametersWithIV)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes256Ecb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });

            blockEncryptor.Add(NttObjectIdentifiers.IdCamellia128Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Camellia.Key(key)).CreateBlockEncryptorBuilder((Camellia.ParametersWithIV)cipherParams); });
            blockEncryptor.Add(NttObjectIdentifiers.IdCamellia192Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Camellia.Key(key)).CreateBlockEncryptorBuilder((Camellia.ParametersWithIV)cipherParams); });
            blockEncryptor.Add(NttObjectIdentifiers.IdCamellia256Cbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Camellia.Key(key)).CreateBlockEncryptorBuilder((Camellia.ParametersWithIV)cipherParams); });

            blockEncryptor.Add(KisaObjectIdentifiers.IdSeedCbc, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new Seed.Key(key)).CreateBlockEncryptorBuilder((Seed.ParametersWithIV)cipherParams); });

            blockEncryptor.Add(NistObjectIdentifiers.IdAes128Ccm, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes128Cfb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });
            
            blockEncryptor.Add(NistObjectIdentifiers.IdAes128Gcm, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });
            blockEncryptor.Add(NistObjectIdentifiers.IdAes128Ofb, (key, cipherParams) => { return CryptoServicesRegistrar.CreateService(new FipsAes.Key(key)).CreateBlockEncryptorBuilder((FipsAes.Parameters)cipherParams); });
        }

        /**
		 * Return the digest algorithm using one of the standard JCA string
		 * representations rather than the algorithm identifier (if possible).
		 */
        private static string GetDigestAlgName(
            DerObjectIdentifier digestAlgOID)
        {
            if (PkcsObjectIdentifiers.MD5.Equals(digestAlgOID))
            {
                return "MD5";
            }
            else if (OiwObjectIdentifiers.IdSha1.Equals(digestAlgOID))
            {
                return "SHA1";
            }
            else if (NistObjectIdentifiers.IdSha224.Equals(digestAlgOID))
            {
                return "SHA224";
            }
            else if (NistObjectIdentifiers.IdSha256.Equals(digestAlgOID))
            {
                return "SHA256";
            }
            else if (NistObjectIdentifiers.IdSha384.Equals(digestAlgOID))
            {
                return "SHA384";
            }
            else if (NistObjectIdentifiers.IdSha512.Equals(digestAlgOID))
            {
                return "SHA512";
            }
            else if (NistObjectIdentifiers.IdSha512_224.Equals(digestAlgOID))
            {
                return "SHA512/224";
            }
            else if (NistObjectIdentifiers.IdSha512_256.Equals(digestAlgOID))
            {
                return "SHA512/224";
            }
            else
            {
                return digestAlgOID.Id;
            }
        }

        internal static string GetSignatureName(AlgorithmIdentifier sigAlgId)
        {
            Asn1Encodable parameters = sigAlgId.Parameters;

            if (parameters != null && !derNull.Equals(parameters))
            {
                if (sigAlgId.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
                {
                    RsassaPssParameters rsaParams = RsassaPssParameters.GetInstance(parameters);

                    return GetDigestAlgName(rsaParams.HashAlgorithm.Algorithm) + "withRSAandMGF1";
                }
                if (sigAlgId.Algorithm.Equals(X9ObjectIdentifiers.ECDsaWithSha2))
                {
                    Asn1Sequence ecDsaParams = Asn1Sequence.GetInstance(parameters);

                    return GetDigestAlgName((DerObjectIdentifier)ecDsaParams[0]) + "withECDSA";
                }
            }

            return sigAlgId.Algorithm.Id;
        }

        private static RsassaPssParameters CreatePssParams(
            AlgorithmIdentifier hashAlgId,
            int saltSize)
        {
            return new RsassaPssParameters(
                hashAlgId,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgId),
                new DerInteger(saltSize),
                new DerInteger(1));
        }

        internal static DerObjectIdentifier GetAlgorithmOid(
            string algorithmName)
        {
            algorithmName = Platform.ToUpperInvariant(algorithmName);

            if (algorithms.Contains(algorithmName))
            {
                return (DerObjectIdentifier)algorithms[algorithmName];
            }

            return new DerObjectIdentifier(algorithmName);
        }

        internal static AlgorithmIdentifier GetSigAlgID(
            DerObjectIdentifier sigOid,
            string algorithmName)
        {
            if (noParams.Contains(sigOid))
            {
                return new AlgorithmIdentifier(sigOid);
            }

            algorithmName = Platform.ToUpperInvariant(algorithmName);

            if (exParams.Contains(algorithmName))
            {
                return new AlgorithmIdentifier(sigOid, (Asn1Encodable)exParams[algorithmName]);
            }

            return new AlgorithmIdentifier(sigOid, DerNull.Instance);
        }

        internal static AlgorithmIdentifier GetSigAlgID(
            IParameters<Algorithm> algDetails)
        {
            AlgorithmIdentifier algId = null;

            FipsRsa.SignatureParameters rsaParams = algDetails as FipsRsa.SignatureParameters;
            if (rsaParams != null)
            {
                if (rsaParams.Algorithm == FipsRsa.Pkcs1v15.Algorithm)
                {
                    algId = (AlgorithmIdentifier)rsaPkcs1Table[rsaParams.DigestAlgorithm];
                }
                if (algId != null)
                {
                    return algId;
                }
            }

            FipsRsa.PssSignatureParameters rsaPssParams = algDetails as FipsRsa.PssSignatureParameters;
            if (rsaPssParams != null)
            {
                if (rsaPssParams.DigestAlgorithm == rsaPssParams.MgfDigestAlgorithm)
                {
                    AlgorithmIdentifier digAlgId = (AlgorithmIdentifier)pssTable[rsaPssParams.DigestAlgorithm];
                    if (digAlgId != null)
                    {
                        return new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsassaPss, new RsassaPssParameters(digAlgId, 
                            new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, digAlgId), new DerInteger(rsaPssParams.SaltLength), new DerInteger(1)));
                    }
                }
            }

            FipsEC.SignatureParameters ecParams = algDetails as FipsEC.SignatureParameters;
            if (ecParams != null)
            {
                algId = (AlgorithmIdentifier)ecdsaTable[ecParams.DigestAlgorithm];
                if (algId != null)
                {
                    return algId;
                }
            }

            FipsDsa.SignatureParameters dsaParams = algDetails as FipsDsa.SignatureParameters;
            if (dsaParams != null)
            {
                algId = (AlgorithmIdentifier)dsaTable[dsaParams.DigestAlgorithm];
                if (algId != null)
                {
                    return algId;
                }
            }

            EC.SignatureParameters genEcParams = algDetails as EC.SignatureParameters;
            if (genEcParams != null)
            {
                algId = (AlgorithmIdentifier)ecdsaTable[genEcParams.DigestAlgorithm];
                if (algId != null)
                {
                    return algId;
                }
            }

            Dsa.SignatureParameters genDsaParams = algDetails as Dsa.SignatureParameters;
            if (genDsaParams != null)
            {
                algId = (AlgorithmIdentifier)dsaTable[genDsaParams.DigestAlgorithm];
                if (algId != null)
                {
                    return algId;
                }
            }

            Sphincs.SignatureParameters genSphincsParams = algDetails as Sphincs.SignatureParameters;
            if (genSphincsParams != null)
            {
                if (genSphincsParams.DigestAlgorithm == FipsShs.Sha512)
                {
                    return new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256_with_SHA512);
                }
                else
                {
                    return new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256_with_SHA3_512);
                }
            }

            throw new ArgumentException("unknown signature algorithm");
        }

        internal static ICollection<string> GetAlgNames()
        {
            return (ICollection<string>)algorithms.Keys;
        }

        internal static bool IsBlockMode(Algorithm algorithm)
        {
            return algorithm.Mode == AlgorithmMode.ECB || algorithm.Mode == AlgorithmMode.CBC;
        }

        internal static bool IsAeadMode(Algorithm algorithm)
        {
            return algorithm.Mode == AlgorithmMode.CCM || algorithm.Mode == AlgorithmMode.GCM;
        }

        internal static bool IsAeadMode(DerObjectIdentifier algorithm)
        {
            return aeadModes.Contains(algorithm);
        }

        internal static EncryptionScheme GetEncryptionSchemeIdentifier(DerObjectIdentifier keyEncAlgorithm, SecureRandom random)
        {
            int ivLength = (int)Utils.ivSizesInBytes[keyEncAlgorithm];
            byte[] iv = null;

            if (ivLength != 0)
            {
                iv = new byte[ivLength];
                if (random != null)
                {
                    random.NextBytes(iv);
                }
                else
                {
                    CryptoServicesRegistrar.GetSecureRandom().NextBytes(iv);
                }
            }

            EncryptionScheme encScheme;
            if (Utils.IsAeadMode(keyEncAlgorithm))
            {
                // at the moment GCM/CCM have the same structure
                encScheme = new EncryptionScheme(keyEncAlgorithm, new CcmParameters(iv, 12));
            }
            else
            {
                encScheme = new EncryptionScheme(keyEncAlgorithm, new DerOctetString(iv));
            }

            return encScheme;
        }

        internal static IParameters<Algorithm> GetCipherParameters(AlgorithmIdentifier encScheme)
        {
            DerObjectIdentifier encSchemeAlg = encScheme.Algorithm;

            if (encSchemeAlg.On(NistObjectIdentifiers.Aes))
            {
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ecb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ecb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ecb))
                {
                    return FipsAes.Ecb;
                }

                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Cbc) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Cbc) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Cbc))
                {
                    byte[] iv = DerOctetString.GetInstance(encScheme.Parameters).GetOctets();

                    return FipsAes.Cbc.WithIV(iv);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Cfb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Cfb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Cfb))
                {
                    byte[] iv = DerOctetString.GetInstance(encScheme.Parameters).GetOctets();

                    return FipsAes.Cfb128.WithIV(iv);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ofb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ofb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ofb))
                {
                    byte[] iv = DerOctetString.GetInstance(encScheme.Parameters).GetOctets();

                    return FipsAes.Ofb.WithIV(iv);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ccm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ccm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ccm))
                {
                    CcmParameters authParams = CcmParameters.GetInstance(encScheme.Parameters);

                    return FipsAes.Ccm.WithIV(authParams.GetNonce()).WithMacSize(authParams.IcvLen * 8);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Gcm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Gcm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Gcm))
                {
                    GcmParameters authParams = GcmParameters.GetInstance(encScheme.Parameters);

                    return FipsAes.Ccm.WithIV(authParams.GetNonce()).WithMacSize(authParams.IcvLen * 8);
                }
            }

            if (encSchemeAlg.Equals(NttObjectIdentifiers.IdCamellia128Cbc) || encSchemeAlg.Equals(NttObjectIdentifiers.IdCamellia192Cbc) || encSchemeAlg.Equals(NttObjectIdentifiers.IdCamellia256Cbc))
            {
                byte[] iv = DerOctetString.GetInstance(encScheme.Parameters).GetOctets();

                return Camellia.Cbc.WithIV(iv);
            }

            if (encSchemeAlg.Equals(PkcsObjectIdentifiers.DesEde3Cbc))
            {
                byte[] iv = DerOctetString.GetInstance(encScheme.Parameters).GetOctets();

                return FipsTripleDes.Cbc.WithIV(iv);
            }

            if (encSchemeAlg.Equals(KisaObjectIdentifiers.IdSeedCbc))
            {
                byte[] iv = DerOctetString.GetInstance(encScheme.Parameters).GetOctets();

                return Seed.Cbc.WithIV(iv);
            }


            throw new ArgumentException("cannot match algorithm");
        }

        internal static ICipherBuilder<IParameters<Algorithm>> CreateDecryptorBuilder(AlgorithmIdentifier encScheme, byte[] derivedKey, IParameters<Algorithm> parameters)
        {
            DerObjectIdentifier encSchemeAlg = encScheme.Algorithm;

            if (encSchemeAlg.On(NistObjectIdentifiers.Aes))
            {
                IAeadBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsAes.Key(derivedKey));

                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Cfb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Cfb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Cfb))
                {
                    return service.CreateDecryptorBuilder(parameters);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ofb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ofb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ofb))
                {
                    return service.CreateDecryptorBuilder(parameters);
                }
            }

            throw new ArgumentException("cannot match decryption algorithm");
        }

        internal static IAeadCipherBuilder<IParameters<Algorithm>> CreateAeadDecryptorBuilder(AlgorithmIdentifier encScheme, byte[] derivedKey, IParameters<Algorithm> parameters)
        {
            DerObjectIdentifier encSchemeAlg = encScheme.Algorithm;

            if (encSchemeAlg.On(NistObjectIdentifiers.Aes))
            {
                IAeadBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsAes.Key(derivedKey));

                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ccm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ccm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ccm))
                {
                    return service.CreateAeadDecryptorBuilder((FipsAes.AuthenticationParametersWithIV)parameters);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Gcm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Gcm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Gcm))
                {
                    return service.CreateAeadDecryptorBuilder((FipsAes.AuthenticationParametersWithIV)parameters);
                }
            }

            throw new ArgumentException("cannot match decryption algorithm");
        }

        internal static IBlockCipherBuilder<IParameters<Algorithm>> CreateBlockDecryptorBuilder(AlgorithmIdentifier encScheme, byte[] derivedKey, IParameters<Algorithm> cipherParams)
        {
            DerObjectIdentifier encSchemeAlg = encScheme.Algorithm;
            if (!blockDecryptor.ContainsKey(encSchemeAlg))
            {
                throw new ArgumentException("cannot match decryption algorithm");
            }
            return blockDecryptor[encSchemeAlg](derivedKey, cipherParams);
        }

        internal static IBlockCipherBuilder<IParameters<Algorithm>> CreateDecryptorBuilder(AlgorithmIdentifier encScheme, byte[] derivedKey, byte[] iv)
        {
            DerObjectIdentifier encSchemeAlg = encScheme.Algorithm;

            if (encSchemeAlg.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc))
            {
                IBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(derivedKey));

                return service.CreateBlockDecryptorBuilder(FipsTripleDes.Cbc.WithIV(iv));
            }
            if (encSchemeAlg.Equals(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc))
            {
                IBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(derivedKey));

                return service.CreateBlockDecryptorBuilder(FipsTripleDes.Cbc.WithIV(iv));
            }
            throw new ArgumentException("cannot match decryption algorithm");
        }

        internal static ICipherBuilder<IParameters<Algorithm>> CreateEncryptorBuilder(DerObjectIdentifier keyEncAlgorithm, byte[] derivedKey, IParameters<Algorithm> parameters)
        {
            DerObjectIdentifier encSchemeAlg = keyEncAlgorithm;

            if (encSchemeAlg.On(NistObjectIdentifiers.Aes))
            {
                IAeadBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsAes.Key(derivedKey));

                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Cfb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Cfb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Cfb))
                {
                    return service.CreateEncryptorBuilder((FipsAes.ParametersWithIV)parameters);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ofb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ofb) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ofb))
                {
                    return service.CreateEncryptorBuilder((FipsAes.ParametersWithIV)parameters);
                }
            }

            throw new ArgumentException("cannot match encryption algorithm");
        }

        internal static IAeadCipherBuilder<IParameters<Algorithm>> CreateAeadEncryptorBuilder(DerObjectIdentifier keyEncAlgorithm, byte[] derivedKey, IParameters<Algorithm> parameters)
        {
            DerObjectIdentifier encSchemeAlg = keyEncAlgorithm;

            if (encSchemeAlg.On(NistObjectIdentifiers.Aes))
            {
                IAeadBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsAes.Key(derivedKey));

                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Ccm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Ccm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Ccm))
                {
                    return service.CreateAeadEncryptorBuilder((FipsAes.AuthenticationParametersWithIV)parameters);
                }
                if (encSchemeAlg.Equals(NistObjectIdentifiers.IdAes128Gcm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes192Gcm) || encSchemeAlg.Equals(NistObjectIdentifiers.IdAes256Gcm))
                {
                    return service.CreateAeadEncryptorBuilder((FipsAes.AuthenticationParametersWithIV)parameters);
                }
            }

            throw new ArgumentException("cannot match encryption algorithm");
        }

        internal static IBlockCipherBuilder<IParameters<Algorithm>> CreateBlockEncryptorBuilder(DerObjectIdentifier keyEncAlgorithm, byte[] derivedKey, IParameters<Algorithm> cipherParams)
        {
            if (!blockEncryptor.ContainsKey(keyEncAlgorithm))
            {
                throw new ArgumentException("cannot match encryption algorithm");
            }
            return blockEncryptor[keyEncAlgorithm](derivedKey, cipherParams);
        }

        internal static IBlockCipherBuilder<IParameters<Algorithm>> CreateBlockEncryptorBuilder(AlgorithmIdentifier encScheme, byte[] derivedKey, byte[] iv)
        {
            DerObjectIdentifier encSchemeAlg = encScheme.Algorithm;

            if (encSchemeAlg.Equals(PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc))
            {
                IBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(derivedKey));

                return service.CreateBlockEncryptorBuilder(FipsTripleDes.Cbc.WithIV(iv));
            }
            if (encSchemeAlg.Equals(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc))
            {
                IBlockCipherService service = CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(derivedKey));

                return service.CreateBlockEncryptorBuilder(FipsTripleDes.Cbc.WithIV(iv));
            }
            throw new ArgumentException("cannot match decryption algorithm");
        }
    }
}
