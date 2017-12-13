using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;


namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// A class for creating EncryptedPrivateKeyInfo structures.
    /// <code>
    /// EncryptedPrivateKeyInfo ::= SEQUENCE {
    ///        encryptionAlgorithm AlgorithmIdentifier { { KeyEncryptionAlgorithms } },
    ///        encryptedData EncryptedData
    /// }
    ///
    /// EncryptedData ::= OCTET STRING
    ///
    /// KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER::= {
    ///          ... -- For local profiles
    /// }
    /// </code>
    /// </summary>
    public class Pkcs8EncryptedPrivateKeyInfoBuilder
    {
        private PrivateKeyInfo privateKeyInfo;

        /// <summary>
        /// Constructor using an encoded PrivateKeyInfo object.
        /// </summary>
        /// <param name="encodedPrivateKeyInfo">a ASN.1 BER encoded PrivateKeyInfo object.</param>
        public Pkcs8EncryptedPrivateKeyInfoBuilder(byte[] encodedPrivateKeyInfo): this(PrivateKeyInfo.GetInstance(encodedPrivateKeyInfo))
        {
        }

        /// <summary>
        /// Constructor using a PrivateKeyInfo object.
        /// </summary>
        /// <param name="privateKeyInfo">the PrivateKeyInfo to be processed.</param>
        public Pkcs8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo privateKeyInfo)
        {
            this.privateKeyInfo = privateKeyInfo;
        }

        /// <summary>
        /// Create the encrypted private key info using the passed in encryptor.
        /// </summary>
        /// <param name="encryptor">The encryptor to use.</param>
        /// <returns>An encrypted private key info containing the original private key info.</returns>
        public Pkcs8EncryptedPrivateKeyInfo Build(
            ICipherBuilder<AlgorithmIdentifier> encryptor)
        {
            try
            {
                MemoryStream bOut = new MemoryOutputStream();
                ICipher cOut = encryptor.BuildCipher(bOut);
                byte[] keyData = privateKeyInfo.GetEncoded();

                using (var str = cOut.Stream)
                {
                    str.Write(keyData, 0, keyData.Length);
                }

                return new Pkcs8EncryptedPrivateKeyInfo(new EncryptedPrivateKeyInfo(encryptor.AlgorithmDetails, bOut.ToArray()));
            }
            catch (IOException)
            {
                throw new InvalidOperationException("cannot encode privateKeyInfo");
            }
        }
    }
}
