
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Fips
{
    internal class FipsKats
    {
        public enum Vec
        {
            AesEcbEnc,
            AesEcbDec,
            AesCcmEnc,
            AesCcmEncTag,
            AesCcmDec,
            AesCcmDecTag,
            AesCMacTag,
            AesGcmEnc,
            AesGcmEncTag,
            AesGcmDec,
            AesGcmDecTag,
            DrbgCtrTripleDes168_A,
            DrbgCtrAes128_A,
            DrbgCtrAes192_A,
            DrbgCtrAes256_A,
            DrbgCtrTripleDes168_B,
            DrbgCtrAes128_B,
            DrbgCtrAes192_B,
            DrbgCtrAes256_B,
            DrbgHMacSha1_A,
            DrbgHMacSha224_A,
            DrbgHMacSha256_A,
            DrbgHMacSha384_A,
            DrbgHMacSha512_A,
            DrbgHMacSha512_224_A,
            DrbgHMacSha512_256_A,
            DrbgHMacSha1_B,
            DrbgHMacSha224_B,
            DrbgHMacSha256_B,
            DrbgHMacSha384_B,
            DrbgHMacSha512_B,
            DrbgHMacSha512_224_B,
            DrbgHMacSha512_256_B,
            DrbgSha1_A,
            DrbgSha224_A,
            DrbgSha256_A,
            DrbgSha384_A,
            DrbgSha512_A,
            DrbgSha512_224_A,
            DrbgSha512_256_A,
            DrbgSha1_B,
            DrbgSha224_B,
            DrbgSha256_B,
            DrbgSha384_B,
            DrbgSha512_B,
            DrbgSha512_224_B,
            DrbgSha512_256_B,
            DsaKeyPairConsistencyVec,
            DsaStartupVec,
            ECKeyPairConsistencyVec,
            ECStartupVec,
            ECDHHealthVec,
            ECDHKeyPairConsistencyVec,
            ECPrimitiveStartupVec,
            MD5,
            RsaStartupOaepDec,
            RsaStartupOaepEnc,
            RsaStartupVerifySig,
            RsaStartupResultSig,
            RsaStartupRawDec,
            RsaStartupRawEnc,
            RsaKeyPairConsistencyCheck,
            Sha1,
            Sha224,
            Sha256,
            Sha384,
            Sha512,
            Sha512_224,
            Sha512_256,
            Sha3_224,
            Sha3_256,
            Sha3_384,
            Sha3_512,
            Sha1HMac,
            Sha224HMac,
            Sha256HMac,
            Sha384HMac,
            Sha512HMac,
            Sha512_224HMac,
            Sha512_256HMac,
            Shake128,
            Shake256,
            TripleDesEcbEnc,
            TripleDesEcbDec,
            TripleDesCMacTag,
        }

        internal static IDictionary<Vec, byte[]> Values = new Dictionary<Vec, byte[]>();
        internal static byte[] Noise = Strings.ToByteArray("Bogus Value");

        static FipsKats()
        {
            Values.Add(Vec.AesEcbEnc, Hex.Decode("8ea2b7ca516745bfeafc49904b496089"));
            Values.Add(Vec.AesEcbDec, Hex.Decode("00112233445566778899aabbccddeeff"));
            Values.Add(Vec.AesCcmEnc, Hex.Decode("7162015b4dac255d"));
            Values.Add(Vec.AesCcmEncTag, Hex.Decode("6084341b"));
            Values.Add(Vec.AesCcmDec, Hex.Decode("20212223"));
            Values.Add(Vec.AesCcmDecTag, Hex.Decode("6084341b"));
            Values.Add(Vec.AesCMacTag, Hex.Decode("070a16b46b4d4144f79bdd9dd04a287c"));
            Values.Add(Vec.AesGcmEnc, Hex.Decode("42831ec2217774244b7221b784d0d49c"
                    + "e3aa212f2c02a4e035c17e2329aca12e"
                    + "21d514b25466931c7d8f6a5aac84aa05"
                    + "1ba30b396a0aac973d58e091"));
            Values.Add(Vec.AesGcmEncTag, Hex.Decode("5bc94fbc3221a5db94fae95ae7121a47"));
            Values.Add(Vec.AesGcmDec, Hex.Decode("d9313225f88406e5a55909c5aff5269a"
                    + "86a7a9531534f7da2e4c303d8a318a72"
                    + "1c3c0c95956809532fcf0e2449a6b525"
                    + "b16aedf5aa0de657ba637b39"));
            Values.Add(Vec.AesGcmDecTag, Hex.Decode("5bc94fbc3221a5db94fae95ae7121a47"));
            Values.Add(Vec.DrbgCtrTripleDes168_A, Hex.Decode("37b8b6d90405c2e47726c62bf83705bcfadb4e4239abec8dbdbc1ed544d83e7a7971ef0b7366d860"));
            Values.Add(Vec.DrbgCtrTripleDes168_B, Hex.Decode("f9f2cc6db6b4496f0c0b7005d4e22b6f13034e44a559b03437582eafd4991b27927fbb1faa860ebd"));
            Values.Add(Vec.DrbgCtrAes128_A, Hex.Decode("8339142c7329b506b61514bdb8fd5ad225d72a564b1025000c33c43281ebbe1cddf0eace9493342e"));
            Values.Add(Vec.DrbgCtrAes128_B, Hex.Decode("b6a51deea6c2b019ab9d03ac730388c3af39d41f45c9263008dcf6e1d63dc8e9ad06624a4b5866ef"));
            Values.Add(Vec.DrbgCtrAes192_A, Hex.Decode("f60fc3973fc5815f5515edbd0f7010363ebda8f18b0c2744d17db5fc1a7a9475052bc793baa87a22"));
            Values.Add(Vec.DrbgCtrAes192_B, Hex.Decode("173f3374e076502277f1df52a7cfd694d3cbf03a7e981cf1a9ec36ded6a74aed7e1c4cfa5e149e25"));
            Values.Add(Vec.DrbgCtrAes256_A, Hex.Decode("49e16ad6c600a8b588cd286da27ada60419e3f6df2ad7467e80cc53a3dc8119e2364f3d7d2a44097"));
            Values.Add(Vec.DrbgCtrAes256_B, Hex.Decode("92a0b307629eeccb5370ca718da99bdded5f765b6f634916ab88b92441e8c90b91ef203d8448fda0"));
            Values.Add(Vec.DrbgSha1_A, Hex.Decode("532CA1165DCFF21C55592687639884AF4BC4B057DF8F41DE653AB44E2ADEC7C9303E75ABE277EDBF"));
            Values.Add(Vec.DrbgSha1_B, Hex.Decode("73C2C67C696D686D0C4DBCEB5C2AF7DDF6F020B6874FAE4390F102117ECAAFF54418529A367005A0"));
            Values.Add(Vec.DrbgSha224_A, Hex.Decode("caa6b14c594ad8c7f701ce3925e7e61838cab688064b259f79f2c5e248c400a1acf0adf8b528c0c6"));
            Values.Add(Vec.DrbgSha224_B, Hex.Decode("2d79081d8bbb32536de24f19976fce1e8557c931135f0d6ddaebb5e85b250804aba7204385f11cdd"));
            Values.Add(Vec.DrbgSha256_A, Hex.Decode("de1c6b0fe66e9106e5203fa821ead509dda22d703434d56a974eb94a47c90ca1e16479c239ab6097"));
            Values.Add(Vec.DrbgSha256_B, Hex.Decode("05bfd156e55000ff68d9c71c6e9d240b385d3f0f52c8f2ba98f35a76104060cc7ee87083501eb159"));
            Values.Add(Vec.DrbgSha384_A, Hex.Decode("ceada7e59f8ca5ebc4ebfa2f7b0a48a198fe514af15c49b8dc10cb36471af2cc8d965f20b9a9c525"));
            Values.Add(Vec.DrbgSha384_B, Hex.Decode("18448b9770c247520ef5e28d04c7b47b71a0e833ea86d247cceaee968785f1b421ae65a57acdc2b5"));
            Values.Add(Vec.DrbgSha512_A, Hex.Decode("3feded5e458d0dd793e59530fb50cf74c5a719d0e93c3d8acc6f864b47929649069dc2fbd515223f"));
            Values.Add(Vec.DrbgSha512_B, Hex.Decode("8acec9a5f42a6e071acd568d4c219a92f125c4eadb570c029340c568d98e2f75c21edd34c82b120a"));
            Values.Add(Vec.DrbgSha512_224_A, Hex.Decode("70c52d78b89c808850af16a3be8bcb3d4841555c9bba77eced34b3b554892ba87f1aa312dfed53c4"));
            Values.Add(Vec.DrbgSha512_224_B, Hex.Decode("d7f26f260d38144d4994402754810e76b30f8699bbf6b971b2bd79e9f1645be8b6563bc6469dca57"));
            Values.Add(Vec.DrbgSha512_256_A, Hex.Decode("ce818c49bb4975175db33efd736ae7da12c4d531d5a95f0378cf50adc96d022ad5123d37fe1bf5cf"));
            Values.Add(Vec.DrbgSha512_256_B, Hex.Decode("96ef76a26d5d31cef4835c3871e391d34e51e73fbb58b2d274a0f3ca9f08da5148de3209863d12a5"));
            Values.Add(Vec.DrbgHMacSha1_A, Hex.Decode("6c37fdd729aa40f80bc6ab08ca7cc649794f6998b57081e4220f22c5c283e2c91b8e305ab869c625"));
            Values.Add(Vec.DrbgHMacSha1_B, Hex.Decode("caf57dcfea393b9236bf691fa456fea7fdf1df8361482ca54d5fa723f4c88b4fa504bf03277fa783"));
            Values.Add(Vec.DrbgHMacSha224_A, Hex.Decode("5bb2b7c488c772f2f1244387e12ababc4cff02240bd29f7b51022e238b07f10c3d5d3fbe42caeb21"));
            Values.Add(Vec.DrbgHMacSha224_B, Hex.Decode("7a30c18cddcfcbc9dee0d107e22d57cf96ffc7d1f7d9eebac2862c256d558734aa22e5f5e6c2a7df"));
            Values.Add(Vec.DrbgHMacSha256_A, Hex.Decode("2c332d2c6e24fb45d508614d5af3b1cc604b26c5674865557735b6a2900e39227cd467f0cb7ae0d8"));
            Values.Add(Vec.DrbgHMacSha256_B, Hex.Decode("1a3d5fce46b6b3aebe17b8f6421dfd7fa8dcd0429a749d6d3309f07ff31a742a68eb34bf4104f756"));
            Values.Add(Vec.DrbgHMacSha384_A, Hex.Decode("ec095c82dc870a25ce7b1cdf1e2b88a65cc205255db41b15a70808f122ac83dc4ed64f5c42dcf7e8"));
            Values.Add(Vec.DrbgHMacSha384_B, Hex.Decode("090212d521266e4d6effb79b8f12b629c2b0fea0b4aa0a13fe418c0790bed140585eefbbbc781924"));
            Values.Add(Vec.DrbgHMacSha512_A, Hex.Decode("7d45419aaa268e9ae7c8c6fde3475a524cd1c41760ec312db2e3a5bb9f6f8405ca62040fd3c2bdda"));
            Values.Add(Vec.DrbgHMacSha512_B, Hex.Decode("3bc3a2956673309dcbde9a7491adc4d4b198e8d558e38dba8a33f1bca74ae0e8a598fca41ecfb223"));
            Values.Add(Vec.DrbgHMacSha512_224_A, Hex.Decode("931718bd179349d99882f13c9d16ddba639ae89e6e92ece3a1fd6088fcd0b9821b5cabc804dd1375"));
            Values.Add(Vec.DrbgHMacSha512_224_B, Hex.Decode("6f21305054548f4ff22df977400b2872ca2ae51548b04d1d23efce063922a173e5cac092d18a959d"));
            Values.Add(Vec.DrbgHMacSha512_256_A, Hex.Decode("936ececd2492af2b0635b68ce348d5aa9183e585b7c655169a2b3f20655f30b94fc1c386c8a1a6ae"));
            Values.Add(Vec.DrbgHMacSha512_256_B, Hex.Decode("fa4e1148e8d35dbd47982d78ae7d1b1eb3d6c4241f2c5b84868c019c8dd494cc7704dcc5fdc414fb"));
            Values.Add(Vec.DsaKeyPairConsistencyVec, Hex.Decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc"));
            Values.Add(Vec.DsaStartupVec, Hex.Decode("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"));
            Values.Add(Vec.ECStartupVec, Hex.Decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD"));
            Values.Add(Vec.ECKeyPairConsistencyVec, Hex.Decode("0102030405060708090a1112131415161718191a"));
            Values.Add(Vec.ECDHHealthVec, Hex.Decode("cad5c428ea0645794bc5634549e08a3ed563bd0cf32e909862e08b41d4b6fc17"));
            Values.Add(Vec.ECDHKeyPairConsistencyVec, Hex.Decode("01"));
            Values.Add(Vec.ECPrimitiveStartupVec, Hex.Decode("2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8"));
            Values.Add(Vec.MD5, Hex.Decode("900150983cd24fb0d6963f7d28e17f72"));
            Values.Add(Vec.RsaStartupResultSig, Hex.Decode("1669b752b409a66ca38ba7e34ae2d5da4303c091255989a4369885ecbb25db3ec05b06fdb4b1be46f6ab347bad9dbbbc9facf0beb4be70bd5f2ee2760c76f0a55932dd7fb4fe5c7b18226796f955215ec6354da9b3808a0df8c2a328abdd67d537f967ea5147bb85dcd80fdcee250b9bc7cec84a08afcde82afa4e62d80bbaf00bcdaf6bbac2b4a4bd394ee223ea3ee100fd233dd40514ea7a9717bfb52370eb4157e7bd25396e9dd3e3782ec2c64db71cf8380c05d3941481af3a08003737456a00cb265efc1d0987acae40776fa497681cb987a508419cbe1e4601a5e5aef66329288453003101a375ad3ec6e4b9a82f49a0748eb024fe1ce2de910d823938"));
            Values.Add(Vec.RsaStartupVerifySig, Hex.Decode("1669b752b409a66ca38ba7e34ae2d5da4303c091255989a4369885ecbb25db3ec05b06fdb4b1be46f6ab347bad9dbbbc9facf0beb4be70bd5f2ee2760c76f0a55932dd7fb4fe5c7b18226796f955215ec6354da9b3808a0df8c2a328abdd67d537f967ea5147bb85dcd80fdcee250b9bc7cec84a08afcde82afa4e62d80bbaf00bcdaf6bbac2b4a4bd394ee223ea3ee100fd233dd40514ea7a9717bfb52370eb4157e7bd25396e9dd3e3782ec2c64db71cf8380c05d3941481af3a08003737456a00cb265efc1d0987acae40776fa497681cb987a508419cbe1e4601a5e5aef66329288453003101a375ad3ec6e4b9a82f49a0748eb024fe1ce2de910d823938"));
            Values.Add(Vec.RsaStartupOaepEnc, Hex.Decode(
                        "4458cce0f94ebd79d275a134d224f95ef4126034e5d979359703b466096fcc15b71b78df4d4a68033112dfcfad7611cc" +
                        "0458475ab4a66b815f87fcb16a8aa1133441b9d61ed846c4856c5d42059fab7505bd8ffa5281a2bb187c6c853f298c98" +
                        "d5752a40be905f85e5ccb27d59415f09ac12a1788d654c675d98f412e6481e6f1159f1736dd96b29c99b411b4e5420b5" +
                        "6b07be2885dbc397fa091f66877c41e502cb4afeba460a2ebcdec7d09d933e630b98a4510ad6f32ca7ffc1bdb43e46ff" +
                        "f709819d3a69d9b62b774cb12c9dc176a6911bf370ab5029719dc1b4c13e23e57e46a7cd8ba5ee54c954ed460835ddab" +
                        "0086fa36ac110a5790e82c929bc7ca86"));
            Values.Add(Vec.RsaStartupOaepDec, Hex.Decode("48656c6c6f20776f726c6421"));
            Values.Add(Vec.RsaStartupRawDec, Hex.Decode("ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e"));
            Values.Add(Vec.RsaStartupRawEnc, Hex.Decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc3497a9fb17ba03d95f28fad91247d6f8ebc463fa8ada974f0f4e28961565a73a46a465369e0798ccbf7893cb9afaa7c426cc4fea6f429e67b6205b682a9831337f2548fd165c2dd7bf5b54be5894403d6e9f6283e65fb134cd4687bf86f95e7a"));
            Values.Add(Vec.RsaKeyPairConsistencyCheck, Hex.Decode("576a1f885e3420128c8a656097ba7d8bb4c6f1b1853348cf2ba976971dbdbefc"));
            Values.Add(Vec.Sha1, Hex.Decode("a9993e364706816aba3e25717850c26c9cd0d89d"));
            Values.Add(Vec.Sha224, Hex.Decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
            Values.Add(Vec.Sha256, Hex.Decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
            Values.Add(Vec.Sha384, Hex.Decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
            Values.Add(Vec.Sha512, Hex.Decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
            Values.Add(Vec.Sha512_224, Hex.Decode("4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA"));
            Values.Add(Vec.Sha512_256, Hex.Decode("53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23"));
            Values.Add(Vec.Sha3_224, Hex.Decode("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"));
            Values.Add(Vec.Sha3_256, Hex.Decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
            Values.Add(Vec.Sha3_384, Hex.Decode("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"));
            Values.Add(Vec.Sha3_512, Hex.Decode("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
            Values.Add(Vec.Sha1HMac, Hex.Decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
            Values.Add(Vec.Sha224HMac, Hex.Decode("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"));
            Values.Add(Vec.Sha256HMac, Hex.Decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
            Values.Add(Vec.Sha384HMac, Hex.Decode("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));
            Values.Add(Vec.Sha512HMac, Hex.Decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
            Values.Add(Vec.Sha512_224HMac, Hex.Decode("4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde"));
            Values.Add(Vec.Sha512_256HMac, Hex.Decode("6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"));
            Values.Add(Vec.Shake128, Hex.Decode("5881092dd818bf5cf8a3ddb793fbcba7"));
            Values.Add(Vec.Shake256, Hex.Decode("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"));
            Values.Add(Vec.TripleDesEcbEnc, Hex.Decode("f7cfbe5e6c38b35a62815c962fcaf7a863af5450ec85fdab"));
            Values.Add(Vec.TripleDesEcbDec, Hex.Decode("4e6f77206973207468652074696d6520666f7220616c6c20"));
            Values.Add(Vec.TripleDesCMacTag, Hex.Decode("c0b9bbee139722ab"));
        }

        internal static bool FailKat(Vec katVector)
        {
#if DEBUG
            byte[] kat = Values[katVector];
            if (kat != null)
            {
                for (int i = 0; i != kat.Length; i++)
                {
                    kat[i] ^= Noise[i % Noise.Length];
                }
                return true;
            }
#endif
            return false;
        }
    }
}
