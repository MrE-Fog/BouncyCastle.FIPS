using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;

namespace Org.BouncyCastle.Operators
{
    class OpenSslUtilities
    {
        private class PemCipherImpl : ICipherBuilder<DekInfo>
        {
            private DekInfo dekInfo;
            private ICipherBuilder<IParameters<Algorithm>> baseCipher;

            internal PemCipherImpl(DekInfo dekInfo, ICipherBuilder<IParameters<Algorithm>> baseCipher)
            {
                this.dekInfo = dekInfo;
                this.baseCipher = baseCipher;
            }

            public DekInfo AlgorithmDetails
            {
                get
                {
                    return dekInfo;
                }
            }

            public ICipher BuildCipher(Stream stream)
            {
                return baseCipher.BuildCipher(stream);
            }

            public int GetMaxOutputSize(int inputLen)
            {
                return baseCipher.GetMaxOutputSize(inputLen);
            }
        }

        private class PemBlockCipherImpl : ICipherBuilder<DekInfo>
        {
            private DekInfo dekInfo;
            private IBlockCipherBuilder<IParameters<Algorithm>> baseCipher;

            internal PemBlockCipherImpl(bool forEncryption, DekInfo dekInfo, IBlockCipherBuilder<IParameters<Algorithm>> baseCipher)
            {
                this.dekInfo = dekInfo;
                this.baseCipher = baseCipher;
            }

            public DekInfo AlgorithmDetails
            {
                get
                {
                    return dekInfo;
                }
            }

            public ICipher BuildCipher(Stream stream)
            {
                return baseCipher.BuildPaddedCipher(stream, new Pkcs7Padding());
            }

            public int GetMaxOutputSize(int inputLen)
            {
                return baseCipher.GetMaxOutputSize(inputLen);
            }
        }

        internal static ICipherBuilder<DekInfo> Crypt(
            bool encrypt,
            char[] password,
            String dekAlgName,
            byte[] iv)
        {
            byte[] ivValue = iv;
            String blockMode = "CBC";
            byte[] sKey;
            IBlockCipherService cipherService = null;
            IBlockCipherBuilder<IParameters<Algorithm>> blockCipherBuilder = null;
            ICipherBuilder<IParameters<Algorithm>> cipherBuilder = null;

            DekInfo dekInfo;
            if (iv != null && iv.Length != 0)
            {
                dekInfo = new DekInfo(dekAlgName + "," + Hex.ToHexString(iv));
            }
            else
            {
                dekInfo = new DekInfo(dekAlgName);
            }
            // Figure out block mode and padding.
            if (dekAlgName.EndsWith("-CFB"))
            {
                blockMode = "CFB";
            }
            if (dekAlgName.EndsWith("-ECB") ||
                "DES-EDE".Equals(dekAlgName) ||
                "DES-EDE3".Equals(dekAlgName))
            {
                // ECB is actually the default (though seldom used) when OpenSSL
                // uses DES-EDE (des2) or DES-EDE3 (des3).
                blockMode = "ECB";
            }
            if (dekAlgName.EndsWith("-OFB"))
            {
                blockMode = "OFB";
            }

            // Figure out algorithm and key size.
            if (dekAlgName.StartsWith("DES-EDE"))
            {
                // "DES-EDE" is actually des2 in OpenSSL-speak!
                // "DES-EDE3" is des3.
                bool des2 = !dekAlgName.StartsWith("DES-EDE3");

                FipsTripleDes.Key tdesKey = new FipsTripleDes.Key(getKey(password, 24, iv, des2));
                cipherService = CryptoServicesRegistrar.CreateService(tdesKey);
        
                if (blockMode.Equals("CBC"))
                {
                    if (encrypt)
                    {
                        blockCipherBuilder = cipherService.CreateBlockEncryptorBuilder(FipsTripleDes.Cbc.WithIV(ivValue));
                    }
                    else
                    {
                        blockCipherBuilder = cipherService.CreateBlockDecryptorBuilder(FipsTripleDes.Cbc.WithIV(ivValue));
                    }
                }
                else if (blockMode.Equals("CFB"))
                {
                    if (encrypt)
                    {
                        cipherBuilder = cipherService.CreateEncryptorBuilder(FipsTripleDes.Cfb64.WithIV(ivValue));
                    }
                    else
                    {
                        cipherBuilder = cipherService.CreateDecryptorBuilder(FipsTripleDes.Cfb64.WithIV(ivValue));
                    }
                }
                else if (blockMode.Equals("OFB"))
                {
                    if (encrypt)
                    {
                        cipherBuilder = cipherService.CreateEncryptorBuilder(FipsTripleDes.Ofb.WithIV(ivValue));
                    }
                    else
                    {
                        cipherBuilder = cipherService.CreateDecryptorBuilder(FipsTripleDes.Ofb.WithIV(ivValue));
                    }
                }
                else
                {
                    if (encrypt)
                    {
                        blockCipherBuilder = cipherService.CreateBlockEncryptorBuilder(FipsTripleDes.Ecb);
                    }
                    else
                    {
                        blockCipherBuilder = cipherService.CreateBlockDecryptorBuilder(FipsTripleDes.Ecb);
                    }
                }
            }
            else if (dekAlgName.StartsWith("DES-"))
            {
                sKey = getKey(password, 8, iv);
                throw new InvalidOperationException("no support for DES");
            }
            else if (dekAlgName.StartsWith("BF-"))
            {
                sKey = getKey(password, 16, iv);
                throw new InvalidOperationException("no support for Blowfish");
            }
            else if (dekAlgName.StartsWith("RC2-"))
            {
                int keyBits = 128;
                if (dekAlgName.StartsWith("RC2-40-"))
                {
                    keyBits = 40;
                }
                else if (dekAlgName.StartsWith("RC2-64-"))
                {
                    keyBits = 64;
                }
                //sKey = new RC2Parameters(getKey(password, keyBits / 8, iv).getKey(), keyBits);
                throw new InvalidOperationException("no support for RC2");
            }
            else if (dekAlgName.StartsWith("AES-"))
            {
                byte[] salt = iv;
                if (salt.Length > 8)
                {
                    salt = new byte[8];
                    Array.Copy(iv, 0, salt, 0, 8);
                }

                int keyBits;
                if (dekAlgName.StartsWith("AES-128-"))
                {
                    keyBits = 128;
                }
                else if (dekAlgName.StartsWith("AES-192-"))
                {
                    keyBits = 192;
                }
                else if (dekAlgName.StartsWith("AES-256-"))
                {
                    keyBits = 256;
                }
                else
                {
                    throw new InvalidOperationException("unknown AES encryption with private key: " + dekAlgName);
                }

                FipsAes.Key aesKey = new FipsAes.Key(getKey(password, keyBits / 8, salt));
                cipherService = CryptoServicesRegistrar.CreateService(aesKey);

                if (blockMode.Equals("CBC"))
                {
                    if (encrypt)
                    {
                        blockCipherBuilder = cipherService.CreateBlockEncryptorBuilder(FipsAes.Cbc.WithIV(ivValue));
                    }
                    else
                    {
                        blockCipherBuilder = cipherService.CreateBlockDecryptorBuilder(FipsAes.Cbc.WithIV(ivValue));
                    }
                }
                else if (blockMode.Equals("CFB"))
                {
                    if (encrypt)
                    {
                        cipherBuilder = cipherService.CreateEncryptorBuilder(FipsAes.Cfb128.WithIV(ivValue));
                    }
                    else
                    {
                        cipherBuilder = cipherService.CreateDecryptorBuilder(FipsAes.Cfb128.WithIV(ivValue));
                    }
                }
                else if (blockMode.Equals("OFB"))
                {
                    if (encrypt)
                    {
                        cipherBuilder = cipherService.CreateEncryptorBuilder(FipsAes.Ofb.WithIV(ivValue));
                    }
                    else
                    {
                        cipherBuilder = cipherService.CreateDecryptorBuilder(FipsAes.Ofb.WithIV(ivValue));
                    }
                }
                else
                {
                    if (encrypt)
                    {
                        blockCipherBuilder = cipherService.CreateBlockEncryptorBuilder(FipsAes.Ecb);
                    }
                    else
                    {
                        blockCipherBuilder = cipherService.CreateBlockDecryptorBuilder(FipsAes.Ecb);
                    }
                }
            }
            else
            {
                throw new InvalidOperationException("unknown encryption with private key: " + dekAlgName);
            }

            if (blockMode.Equals("CBC") || blockMode.Equals("ECB"))
            {
                if (encrypt)
                {
                    return new PemBlockCipherImpl(encrypt, dekInfo, blockCipherBuilder);
                }
                else
                {
                    return new PemBlockCipherImpl(encrypt, dekInfo, blockCipherBuilder);
                }
            }
            else
            {
                if (encrypt)
                {
                    return new PemCipherImpl(dekInfo, cipherBuilder);
                }
                else
                {
                    return new PemCipherImpl(dekInfo, cipherBuilder);
                }
            }

        }

        private static byte[] getKey(
            char[] password,
            int keyLength,
            byte[] salt)
        {
            return getKey(password, keyLength, salt, false);
        }

        private static byte[] getKey(
            char[] password,
            int keyLength,
            byte[] salt,
            bool des2)
        {
            IPasswordBasedDeriver<Pbkd.OpenSslParameters> paramsGen = CryptoServicesRegistrar.CreateService(Pbkd.OpenSsl).From(PasswordConverter.ASCII.Convert(password)).WithSalt(salt).Build();

            byte[] derivedKey = paramsGen.DeriveKey(TargetKeyType.CIPHER, keyLength);

            if (des2 && derivedKey.Length == 24)
            {
                // For DES2, we must copy first 8 bytes into the last 8 bytes.
                byte[] key = derivedKey;

                Array.Copy(key, 0, key, 16, 8);

                return key;
            }

            return derivedKey;
        }
    }
}
