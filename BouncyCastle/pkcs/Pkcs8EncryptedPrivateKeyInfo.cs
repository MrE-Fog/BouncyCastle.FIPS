﻿
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// A holding class for a PKCS#8 encrypted private key info object that allows for its decryption.
    /// </summary>
    public class Pkcs8EncryptedPrivateKeyInfo
    {
        private EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

        private static EncryptedPrivateKeyInfo parseBytes(byte[] pkcs8Encoding)
        {
            try
            {
                return EncryptedPrivateKeyInfo.GetInstance(pkcs8Encoding);
            }

            catch (ArgumentException e)
            {
                throw new PkcsIOException("malformed data: " + e.Message, e);
            }
            catch (Exception e)
            {
                throw new PkcsIOException("malformed data: " + e.Message, e);
            }
        }

        /// <summary>
        /// Base constructor from a PKCS#8 EncryptedPrivateKeyInfo object.
        /// </summary>
        /// <param name="encryptedPrivateKeyInfo">A PKCS#8 EncryptedPrivateKeyInfo object.</param>
        public Pkcs8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
        {
            this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
        }

        /// <summary>
        /// Base constructor from a BER encoding of a PKCS#8 EncryptedPrivateKeyInfo object.
        /// </summary>
        /// <param name="encryptedPrivateKeyInfo">A BER encoding of a PKCS#8 EncryptedPrivateKeyInfo objects.</param>
        public Pkcs8EncryptedPrivateKeyInfo(byte[] encryptedPrivateKeyInfo) : this(parseBytes(encryptedPrivateKeyInfo))
        {

        }

        /// <summary>
        /// Returns the underlying ASN.1 structure inside this object.
        /// </summary>
        /// <returns>Return the EncryptedPrivateKeyInfo structure in this object.</returns>
        public EncryptedPrivateKeyInfo ToAsn1Structure()
        {
            return encryptedPrivateKeyInfo;
        }

        /// <summary>
        /// Return a binary ASN.1 encoding of the EncryptedPrivateKeyInfo structure in this object.
        /// </summary>
        /// <returns>A byte array containing the encoded object.</returns>
        public byte[] GetEncoded()
        {
            return encryptedPrivateKeyInfo.GetEncoded();
        }

        /// <summary>
        /// Get a decryptor from the passed in provider and decrypt the encrypted private key info, returning the result.
        /// </summary>
        /// <param name="inputDecryptorProvider">A provider to query for decryptors for the object.</param>
        /// <returns>The decrypted private key info structure.</returns>
        public PrivateKeyInfo DecryptPrivateKeyInfo(IDecryptorBuilderProvider<AlgorithmIdentifier> inputDecryptorProvider)
        {
            try
            {
                ICipherBuilder<AlgorithmIdentifier> decryptorBuilder = inputDecryptorProvider.CreateDecryptorBuilder(encryptedPrivateKeyInfo.EncryptionAlgorithm);

                ICipher encIn = decryptorBuilder.BuildCipher(new MemoryInputStream(encryptedPrivateKeyInfo.GetEncryptedData()));

                using (Stream strm = encIn.Stream)
                {
                    byte[] data = Streams.ReadAll(encIn.Stream);
           
                    return PrivateKeyInfo.GetInstance(data);
                }
            }
            catch (Exception e)
            {
                throw new PkcsException("unable to read encrypted data: " + e.Message, e);
            }
        }
    }
}
