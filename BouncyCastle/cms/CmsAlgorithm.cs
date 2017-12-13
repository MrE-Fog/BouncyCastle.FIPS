using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Cms
{
    public class CmsAlgorithm
    {
        /*
        public static readonly DerObjectIdentifier DESCbc = OiwObjectIdentifiers.desCBC;
        
        public static readonly DerObjectIdentifier RC2Cbc = PkcsObjectIdentifiers.RC2Cbc;
        public static readonly DerObjectIdentifier IDEACbc = new DerObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");
        public static readonly DerObjectIdentifier CAST5Cbc = new DerObjectIdentifier("1.2.840.113533.7.66.10");
        */
        public static readonly DerObjectIdentifier DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;
        public static readonly DerObjectIdentifier Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc;
        public static readonly DerObjectIdentifier Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc;
        public static readonly DerObjectIdentifier Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc;
        public static readonly DerObjectIdentifier Aes128Ccm = NistObjectIdentifiers.IdAes128Ccm;
        public static readonly DerObjectIdentifier Aes192Ccm = NistObjectIdentifiers.IdAes192Ccm;
        public static readonly DerObjectIdentifier Aes256Ccm = NistObjectIdentifiers.IdAes256Ccm;
        public static readonly DerObjectIdentifier Aes128Gcm = NistObjectIdentifiers.IdAes128Gcm;
        public static readonly DerObjectIdentifier Aes192Gcm = NistObjectIdentifiers.IdAes192Gcm;
        public static readonly DerObjectIdentifier Aes256Gcm = NistObjectIdentifiers.IdAes256Gcm;
     
        public static readonly DerObjectIdentifier Camellia128Cbc = NttObjectIdentifiers.IdCamellia128Cbc;
        public static readonly DerObjectIdentifier Camellia192Cbc = NttObjectIdentifiers.IdCamellia192Cbc;
        public static readonly DerObjectIdentifier Camellia256Cbc = NttObjectIdentifiers.IdCamellia256Cbc;
        public static readonly DerObjectIdentifier SeedCbc = KisaObjectIdentifiers.IdSeedCbc;
        /*
     public static readonly DerObjectIdentifier DES_EDE3_WRAP = PkcsObjectIdentifiers.id_alg_CMS3DESwrap;
     public static readonly DerObjectIdentifier Aes128_WRAP = NistObjectIdentifiers.IdAes128_wrap;
     public static readonly DerObjectIdentifier Aes192_WRAP = NistObjectIdentifiers.IdAes192_wrap;
     public static readonly DerObjectIdentifier Aes256_WRAP = NistObjectIdentifiers.IdAes256_wrap;
     public static readonly DerObjectIdentifier CAMELLIA128_WRAP = NttObjectIdentifiers.id_camellia128_wrap;
     public static readonly DerObjectIdentifier CAMELLIA192_WRAP = NttObjectIdentifiers.id_camellia192_wrap;
     public static readonly DerObjectIdentifier CAMELLIA256_WRAP = NttObjectIdentifiers.id_camellia256_wrap;
     public static readonly DerObjectIdentifier SEED_WRAP = KisaObjectIdentifiers.id_npki_app_cmsSeed_wrap;

     public static readonly DerObjectIdentifier ECDH_SHA1KDF = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme;
     public static readonly DerObjectIdentifier ECCDH_SHA1KDF = X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme;
     public static readonly DerObjectIdentifier ECMQV_SHA1KDF = X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme;

     public static readonly DerObjectIdentifier ECDH_SHA224KDF = SecObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme;
     public static readonly DerObjectIdentifier ECCDH_SHA224KDF = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme;
     public static readonly DerObjectIdentifier ECMQV_SHA224KDF = SecObjectIdentifiers.mqvSinglePass_sha224kdf_scheme;

     public static readonly DerObjectIdentifier ECDH_SHA256KDF = SecObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme;
     public static readonly DerObjectIdentifier ECCDH_SHA256KDF = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme;
     public static readonly DerObjectIdentifier ECMQV_SHA256KDF = SecObjectIdentifiers.mqvSinglePass_sha256kdf_scheme;

     public static readonly DerObjectIdentifier ECDH_SHA384KDF = SecObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme;
     public static readonly DerObjectIdentifier ECCDH_SHA384KDF = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme;
     public static readonly DerObjectIdentifier ECMQV_SHA384KDF = SecObjectIdentifiers.mqvSinglePass_sha384kdf_scheme;

     public static readonly DerObjectIdentifier ECDH_SHA512KDF = SecObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme;
     public static readonly DerObjectIdentifier ECCDH_SHA512KDF = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme;
     public static readonly DerObjectIdentifier ECMQV_SHA512KDF = SecObjectIdentifiers.mqvSinglePass_sha512kdf_scheme;
     */

        public static readonly DerObjectIdentifier Sha1 = OiwObjectIdentifiers.IdSha1;
        public static readonly DerObjectIdentifier Sha224 = NistObjectIdentifiers.IdSha224;
        public static readonly DerObjectIdentifier Sha256 = NistObjectIdentifiers.IdSha256;
        public static readonly DerObjectIdentifier Sha384 = NistObjectIdentifiers.IdSha384;
        public static readonly DerObjectIdentifier Sha512 = NistObjectIdentifiers.IdSha512;
        public static readonly DerObjectIdentifier MD5 = PkcsObjectIdentifiers.MD5;
        public static readonly DerObjectIdentifier GostR3411 = CryptoProObjectIdentifiers.GostR3411;
        public static readonly DerObjectIdentifier RipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128;
        public static readonly DerObjectIdentifier RipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160;
        public static readonly DerObjectIdentifier RipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256;
    }
}
