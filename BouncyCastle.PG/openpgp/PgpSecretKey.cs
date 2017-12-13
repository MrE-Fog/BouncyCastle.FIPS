using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using Org.BouncyCastle.Utilities.IO;
using System.Collections.Generic;

namespace Org.BouncyCastle.OpenPgp
{
    /// <remarks>General class to handle a Pgp secret key object.</remarks>
    public class PgpSecretKey
    {
        private readonly SecretKeyPacket secret;
        private readonly PgpPublicKey pub;

        PgpSecretKey(
            SecretKeyPacket secret,
            PgpPublicKey pub)
        {
            this.secret = secret;
            this.pub = pub;
        }


        PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            IPbeSecretKeyEncryptor keyEncryptor) : this(privKey, pubKey, false, keyEncryptor)
        {

        }

        /**
         * Construct a PgpSecretKey using the passed in private key and public key. This constructor will not add any
         * certifications but assumes that pubKey already has what is required.
         *
         * @param privKey the private key component.
         * @param pubKey the public key component.
         * @param checksumCalculator a calculator for the private key checksum
         * @param isMasterKey true if the key is a master key, false otherwise.
         * @param keyEncryptor an encryptor for the key if required (null otherwise).
         * @throws PgpException if there is an issue creating the secret key packet.
         */
        public PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            bool isMasterKey,
            IPbeSecretKeyEncryptor keyEncryptor)
        {
            this.pub = pubKey;
            this.secret = buildSecretKeyPacket(isMasterKey, privKey, pubKey, keyEncryptor);
        }

        private static SecretKeyPacket buildSecretKeyPacket(bool isMasterKey, PgpPrivateKey privKey, PgpPublicKey pubKey, IPbeSecretKeyEncryptor keyEncryptor)
        {
            BcpgObject secKey = (BcpgObject)privKey.Key;

            if (secKey == null)
            {
                if (isMasterKey)
                {
                    return new SecretKeyPacket(pubKey.publicPk, SymmetricKeyAlgorithmTag.Null, null, null, new byte[0]);
                }
                else
                {
                    return new SecretSubkeyPacket(pubKey.publicPk, SymmetricKeyAlgorithmTag.Null, null, null, new byte[0]);
                }
            }

            try
            {
                MemoryOutputStream bOut = new MemoryOutputStream();
                BcpgOutputStream pOut = new BcpgOutputStream(bOut);

                pOut.WriteObject(secKey);

                byte[] keyData = bOut.ToArray();
                byte[] checkData = checksum(keyEncryptor.ChecksumCalculatorFactory, keyData, keyData.Length);

                pOut.Write(checkData, 0, checkData.Length);

                PgpPbeKeyEncryptionParameters encParams = keyEncryptor.AlgorithmDetails;

                SymmetricKeyAlgorithmTag encAlgorithm = (keyEncryptor != null) ? encParams.Algorithm : SymmetricKeyAlgorithmTag.Null;

                if (encAlgorithm != SymmetricKeyAlgorithmTag.Null)
                {
                    keyData = bOut.ToArray(); // include checksum

                    byte[] encData = keyEncryptor.Wrap(keyData).Collect();
                    byte[] iv = encParams.GetIV();

                    S2k s2k = encParams.S2k;

                    int s2kUsage;
                   
                    if (keyEncryptor.ChecksumCalculatorFactory != null)
                    {
                        if (keyEncryptor.ChecksumCalculatorFactory.AlgorithmDetails.Algorithm != HashAlgorithmTag.Sha1)
                        {
                            throw new PgpException("only SHA1 supported for key checksum calculations.");
                        }
                        s2kUsage = SecretKeyPacket.UsageSha1;
                    }
                    else
                    {
                        s2kUsage = SecretKeyPacket.UsageChecksum;
                    }

                    if (isMasterKey)
                    {
                        return new SecretKeyPacket(pubKey.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                    else
                    {
                        return new SecretSubkeyPacket(pubKey.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                    }
                }
                else
                {
                    if (isMasterKey)
                    {
                        return new SecretKeyPacket(pubKey.publicPk, encAlgorithm, null, null, bOut.ToArray());
                    }
                    else
                    {
                        return new SecretSubkeyPacket(pubKey.publicPk, encAlgorithm, null, null, bOut.ToArray());
                    }
                }
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
        }

        /*
         * Construct a PgpSecretKey using the passed in private/public key pair and binding it to the passed in id
         * using a generated certification of certificationLevel. If keyEncryptor.ChecksumCalculatorFactory returns null
         * the secret key checksum is calculated using the original
         * non-digest based checksum.
         *
         * @param certificationLevel the type of certification to be added.
         * @param keyPair the public/private keys to use.
         * @param id the id to bind to the key.
         * @param hashedPcks the hashed packets to be added to the certification.
         * @param unhashedPcks the unhashed packets to be added to the certification.
         * @param certificationSignerBuilder the builder for generating the certification.
         * @param keyEncryptor an encryptor for the key if required (null otherwise).
         * @throws PgpException if there is an issue creating the secret key packet or the certification.
         */
        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            String id,
            PgpSignatureSubpacketVector hashedPcks,
            PgpSignatureSubpacketVector unhashedPcks,
            ISignatureWithDigestFactory<PgpSignatureIdentifier> certificationSignerBuilder,
            IPbeSecretKeyEncryptor keyEncryptor) : this(keyPair.PrivateKey, certifiedPublicKey(certificationLevel, keyPair, id, hashedPcks, unhashedPcks, certificationSignerBuilder), true, keyEncryptor)
        {

        }

        private static PgpPublicKey certifiedPublicKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            String id,
            PgpSignatureSubpacketVector hashedPcks,
            PgpSignatureSubpacketVector unhashedPcks,
            ISignatureWithDigestFactory<PgpSignatureIdentifier> certificationSignerBuilder)
        {
            PgpSignatureGenerator sGen;

            try
            {
                sGen = new PgpSignatureGenerator();
            }
            catch (Exception e)
            {
                throw new PgpException("creating signature generator: " + e, e);
            }

            //
            // generate the certification
            //
            sGen.InitSign(certificationLevel, certificationSignerBuilder);

            sGen.SetHashedSubpackets(hashedPcks);
            sGen.SetUnhashedSubpackets(unhashedPcks);

            try
            {
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);

                return PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);
            }
            catch (Exception e)
            {
                throw new PgpException("exception doing certification: " + e, e);
            }
        }

        /**
         * Return true if this key has an algorithm type that makes it suitable to use for signing.
         * <p>
         * Note: with version 4 keys KeyFlags subpackets should also be considered when present for
         * determining the preferred use of the key.
         *
         * @return true if this key algorithm is suitable for use with signing.
         */
        public bool IsSigningKey
        {
            get
            {
                PublicKeyAlgorithmTag algorithm = pub.Algorithm;

                return ((algorithm == PublicKeyAlgorithmTag.RsaGeneral) || (algorithm == PublicKeyAlgorithmTag.RsaSign)
                            || (algorithm == PublicKeyAlgorithmTag.Dsa) || (algorithm == PublicKeyAlgorithmTag.ECDsa) || (algorithm == PublicKeyAlgorithmTag.ElGamalGeneral));
            }
        }

        /**
         * Return true if this is a master key.
         * @return true if a master key.
         */
        public bool IsMasterKey
        {
            get
            {
                return pub.IsMasterKey;
            }
        }

        /**
         * Detect if the Secret Key's Private Key is empty or not
         *
         * @return bool whether or not the private key is empty
         */
        public bool IsPrivateKeyEmpty
        {
            get
            {
                byte[] secKeyData = secret.GetSecretKeyData();

                return (secKeyData == null || secKeyData.Length < 1);
            }
        }

        /**
         * return the algorithm the key is encrypted with.
         *
         * @return the algorithm used to encrypt the secret key.
         */
        public SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm
        {
            get
            {
                return secret.EncAlgorithm;
            }
        }

        /**
         * Return the keyID of the public key associated with this key.
         * 
         * @return the keyID associated with this key.
         */
        public long KeyId
        {
            get
            {
                return pub.KeyId;
            }
        }

        /**
         * Return the S2K usage associated with this key.
         *
         * @return the key's S2K usage
         */
        public int S2kUsage
        {
            get
            {
                return secret.S2kUsage;
            }
        }

        /**
         * Return the S2K used to process this key
         *
         * @return the key's S2K, null if one is not present.
         */
        public S2k S2k
        {
            get
            {
                return secret.S2k;
            }
        }

        /**
         * Return the public key associated with this key.
         * 
         * @return the public key for this key.
         */
        public PgpPublicKey PublicKey
        {
            get
            {
                return pub;
            }
        }

        /**
         * Return any userIDs associated with the key.
         * 
         * @return an iterator of Strings.
         */
        public IEnumerable GetUserIDs()
        {
            return pub.GetUserIds();
        }

        /**
         * Return any user attribute vectors associated with the key.
         * 
         * @return an iterator of PgpUserAttributeSubpacketVector.
         */
        public IEnumerable GetUserAttributes()
        {
            return pub.GetUserAttributes();
        }

        private byte[] extractKeyData(
            IPbeSecretKeyDecryptorProvider decryptorFactory)
        {
            byte[] encData = secret.GetSecretKeyData();
            byte[] data;
            if (secret.EncAlgorithm != SymmetricKeyAlgorithmTag.Null)
            {
                try
                {
                    if (secret.PublicKeyPacket.Version == 4)
                    {
                        IKeyUnwrapper<PgpPbeKeyEncryptionParameters> unwrapper = decryptorFactory.CreateKeyUnwrapper(new PgpPbeKeyEncryptionParameters(secret.EncAlgorithm, secret.S2k, secret.GetIV()));

                        data = unwrapper.Unwrap(encData, 0, encData.Length).Collect();

                        bool useSHA1 = secret.S2kUsage == SecretKeyPacket.UsageSha1;
                        byte[] check = checksum(useSHA1 ? decryptorFactory.CreateDigestFactory(new PgpDigestTypeIdentifier(HashAlgorithmTag.Sha1)) : null, data, (useSHA1) ? data.Length - 20 : data.Length - 2);

                        for (int i = 0; i != check.Length; i++)
                        {
                            if (check[i] != data[data.Length - check.Length + i])
                            {
                                throw new PgpException("checksum mismatch at " + i + " of " + check.Length);
                            }
                        }
                    }
                    else // version 2 or 3, Rsa only.
                    {
                        IKeyUnwrapper<PgpPbeKeyEncryptionParameters> unwrapper = decryptorFactory.CreateKeyUnwrapper(new PgpPbeKeyEncryptionParameters(secret.EncAlgorithm, secret.S2k, secret.GetIV()));

                        data = new byte[encData.Length];

                        byte[] iv = new byte[secret.GetIV().Length];

                        Array.Copy(secret.GetIV(), 0, iv, 0, iv.Length);

                        //
                        // read in the four numbers
                        //
                        int pos = 0;

                        for (int i = 0; i != 4; i++)
                        {
                            int encLen = (((encData[pos] << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                            data[pos] = encData[pos];
                            data[pos + 1] = encData[pos + 1];

                            byte[] tmp = unwrapper.Unwrap(encData, pos + 2, encLen).Collect();
                            Array.Copy(tmp, 0, data, pos + 2, tmp.Length);
                            pos += 2 + encLen;

                            if (i != 3)
                            {
                                Array.Copy(encData, pos - iv.Length, iv, 0, iv.Length);
                            }
                        }

                        //
                        // verify and copy checksum
                        //

                        data[pos] = encData[pos];
                        data[pos + 1] = encData[pos + 1];

                        int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                        int calcCs = 0;
                        for (int j = 0; j < data.Length - 2; j++)
                        {
                            calcCs += data[j] & 0xff;
                        }

                        calcCs &= 0xffff;
                        if (calcCs != cs)
                        {
                            throw new PgpException("checksum mismatch: passphrase wrong, expected "
                                + cs.ToString("X")
                                + " found " + calcCs.ToString("X"));
                        }
                    }
                }
                catch (PgpException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception decrypting key", e);
                }
            }
            else
            {
                data = encData;
            }

            return data;
        }

        /**
         * Extract a PgpPrivate key from the SecretKey's encrypted contents.
         *
         * @param decryptorFactory  factory to use to generate a decryptor for the passed in secretKey.
         * @return PgpPrivateKey  the unencrypted private key.
         * @throws PgpException on failure.
         */
        public PgpPrivateKey ExtractPrivateKey(
            IPbeSecretKeyDecryptorProvider decryptorProvider)
        {
            if (IsPrivateKeyEmpty)
            {
                return null;
            }

            PublicKeyPacket pubPk = secret.PublicKeyPacket;

            try
            {
                byte[] data = extractKeyData(decryptorProvider);
                BcpgInputStream input = BcpgInputStream.Wrap(new MemoryInputStream(data));


                switch (pubPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                        RsaSecretBcpgKey rsaPriv = new RsaSecretBcpgKey(input);

                        return new PgpPrivateKey(this.KeyId, pubPk, rsaPriv);
                    case PublicKeyAlgorithmTag.Dsa:
                        DsaSecretBcpgKey dsaPriv = new DsaSecretBcpgKey(input);

                        return new PgpPrivateKey(this.KeyId, pubPk, dsaPriv);
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        ElGamalSecretBcpgKey elPriv = new ElGamalSecretBcpgKey(input);

                        return new PgpPrivateKey(this.KeyId, pubPk, elPriv);
                    case PublicKeyAlgorithmTag.ECDH:
                    case PublicKeyAlgorithmTag.ECDsa:
                        ECSecretBcpgKey ecPriv = new ECSecretBcpgKey(input);

                        return new PgpPrivateKey(this.KeyId, pubPk, ecPriv);
                    default:
                        throw new PgpException("unknown public key algorithm encountered");
                }
            }
            catch (PgpException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception constructing key", e);
            }
        }

        private static byte[] checksum(IDigestFactory<PgpDigestTypeIdentifier> digCalcFactory, byte[] bytes, int length)
        {
            if (digCalcFactory != null)
            {
                IStreamCalculator<IBlockResult> digCalc = digCalcFactory.CreateCalculator();
                Stream dOut = digCalc.Stream;

                try
                {
                    dOut.Write(bytes, 0, length);

                    dOut.Close();
                }
                catch (Exception e)
                {
                    throw new PgpException("checksum digest calculation failed: " + e.Message, e);
                }
                return digCalc.GetResult().Collect();
            }
            else
            {
                int checksum = 0;

                for (int i = 0; i != length; i++)
                {
                    checksum += bytes[i] & 0xff;
                }

                byte[] check = new byte[2];

                check[0] = (byte)(checksum >> 8);
                check[1] = (byte)checksum;

                return check;
            }
        }

        public byte[] GetEncoded()
        {
            MemoryOutputStream bOut = new MemoryOutputStream();


            this.Encode(bOut);

            return bOut.ToArray();
        }

        public void Encode(
            Stream outStream)
        {
            BcpgOutputStream output = BcpgOutputStream.Wrap(outStream);

            output.WritePacket(secret);
            if (pub.trustPk != null)
            {
                output.WritePacket(pub.trustPk);
            }

            if (pub.subSigs == null)        // is not a sub key
            {
                for (int i = 0; i != pub.keySigs.Count; i++)
                {
                    ((PgpSignature)pub.keySigs[i]).Encode(output);
                }

                for (int i = 0; i != pub.ids.Count; i++)
                {
                    if (pub.ids[i] is UserIdPacket)
                    {
                        UserIdPacket id = (UserIdPacket)pub.ids[i];

                        output.WritePacket(id);
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)pub.ids[i];

                        output.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (pub.idTrusts[i] != null)
                    {
                        output.WritePacket((ContainedPacket)pub.idTrusts[i]);
                    }

                    List<PgpSignature> sigs = pub.idSigs[i];

                    for (int j = 0; j != sigs.Count; j++)
                    {
                        sigs[j].Encode(output);
                    }
                }
            }
            else
            {
                for (int j = 0; j != pub.subSigs.Count; j++)
                {
                    ((PgpSignature)pub.subSigs[j]).Encode(output);
                }
            }
        }

        /**
         * Return a copy of the passed in secret key, encrypted using a new
         * password and the passed in algorithm.
         *
         * @param key the PgpSecretKey to be copied.
         * @param oldKeyDecryptor the current decryptor based on the current password for key.
         * @param newKeyEncryptor a new encryptor based on a new password for encrypting the secret key material.
         */
        public static PgpSecretKey CopyWithNewPassword(
            PgpSecretKey key,
            IPbeSecretKeyDecryptorProvider oldKeyDecryptor,
            IPbeSecretKeyEncryptor newKeyEncryptor)
        {
            if (key.IsPrivateKeyEmpty)
            {
                throw new PgpException("no private key in this SecretKey - public key present only.");
            }

            byte[] rawKeyData = key.extractKeyData(oldKeyDecryptor);
            int s2kUsage = key.secret.S2kUsage;
            byte[] iv = null;
            S2k s2k = null;
            byte[] keyData = null;
            SymmetricKeyAlgorithmTag newEncAlgorithm = SymmetricKeyAlgorithmTag.Null;

            if (newKeyEncryptor == null || newKeyEncryptor.AlgorithmDetails.Algorithm == SymmetricKeyAlgorithmTag.Null)
            {
                s2kUsage = SecretKeyPacket.UsageNone;
                if (key.secret.S2kUsage == SecretKeyPacket.UsageSha1)   // SHA-1 hash, need to rewrite checksum
                {
                    keyData = new byte[rawKeyData.Length - 18];

                    Array.Copy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

                    byte[] check = checksum(null, keyData, keyData.Length - 2);

                    keyData[keyData.Length - 2] = check[0];
                    keyData[keyData.Length - 1] = check[1];
                }
                else
                {
                    keyData = rawKeyData;
                }
            }
            else
            {
                if (s2kUsage == SecretKeyPacket.UsageNone)
                {
                    s2kUsage = SecretKeyPacket.UsageChecksum;
                }
                if (key.secret.PublicKeyPacket.Version < 4)
                {
                    // Version 2 or 3 - RSA Keys only
                    keyData = new byte[rawKeyData.Length];

                    if (newKeyEncryptor.ChecksumCalculatorFactory.AlgorithmDetails.Algorithm != HashAlgorithmTag.MD5)
                    {
                        throw new PgpException("MD5 Digest Calculator required for version 3 key encryptor.");
                    }

                    //
                    // process 4 numbers
                    //
                    int pos = 0;
                    for (int i = 0; i != 4; i++)
                    {
                        int encLen = (((rawKeyData[pos] << 8) | (rawKeyData[pos + 1] & 0xff)) + 7) / 8;

                        keyData[pos] = rawKeyData[pos];
                        keyData[pos + 1] = rawKeyData[pos + 1];

                        byte[] tmp;

                        if (i == 0)
                        {
                            tmp = newKeyEncryptor.Wrap(Arrays.CopyOfRange(rawKeyData, pos + 2, pos + 2 + encLen)).Collect();
                            iv = newKeyEncryptor.AlgorithmDetails.GetIV();
                        }
                        else
                        {
                            byte[] tmpIv = new byte[iv.Length];

                            Array.Copy(keyData, pos - iv.Length, tmpIv, 0, tmpIv.Length);
                            newKeyEncryptor = newKeyEncryptor.WithIV(tmpIv);
                            tmp = newKeyEncryptor.Wrap(Arrays.CopyOfRange(rawKeyData, pos + 2, pos + 2 + encLen)).Collect();
                        }

                        Array.Copy(tmp, 0, keyData, pos + 2, tmp.Length);
                        pos += 2 + encLen;
                    }

                    //
                    // copy in checksum.
                    //
                    keyData[pos] = rawKeyData[pos];
                    keyData[pos + 1] = rawKeyData[pos + 1];

                    s2k = newKeyEncryptor.AlgorithmDetails.S2k;
                    newEncAlgorithm = newKeyEncryptor.AlgorithmDetails.Algorithm;
                }
                else
                {
                    keyData = newKeyEncryptor.Wrap(rawKeyData).Collect();

                    iv = newKeyEncryptor.AlgorithmDetails.GetIV();

                    s2k = newKeyEncryptor.AlgorithmDetails.S2k;

                    newEncAlgorithm = newKeyEncryptor.AlgorithmDetails.Algorithm;
                }
            }
        
            SecretKeyPacket secret;
            if (key.secret is SecretSubkeyPacket)
            {
                secret = new SecretSubkeyPacket(key.secret.PublicKeyPacket,
                    newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(key.secret.PublicKeyPacket,
                    newEncAlgorithm, s2kUsage, s2k, iv, keyData);
            }

            return new PgpSecretKey(secret, key.pub);
        }

        /**
         * Replace the passed the public key on the passed in secret key.
         *
         * @param secretKey secret key to change
         * @param publicKey new public key.
         * @return a new secret key.
         * @throws IllegalArgumentException if keyIDs do not match.
         */
        public static PgpSecretKey ReplacePublicKey(PgpSecretKey secretKey, PgpPublicKey publicKey)
        {
            if (publicKey.KeyId != secretKey.KeyId)
            {
                throw new ArgumentException("keyIDs do not match");
            }

            return new PgpSecretKey(secretKey.secret, publicKey);
        }

        /**
         * Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
         *
         * @return a secret key object.
         */
         /*
        public static PgpSecretKey parseSecretKeyFromSExpr(Stream inputStream, PbeProtectionRemoverFactory keyProtectionRemoverFactory, PgpPublicKey pubKey)
        {
            SXprUtilities.SkipOpenParenthesis(inputStream);

            String type;

            type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
            if (type.Equals("protected-private-key"))
            {
                SXprUtilities.SkipOpenParenthesis(inputStream);

                String curveName;

                String keyType = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (keyType.Equals("ecc"))
                {
                    SXprUtilities.SkipOpenParenthesis(inputStream);

                    String curveID = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                    curveName = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());

                    SXprUtilities.SkipCloseParenthesis(inputStream);
                }
                else
                {
                    throw new PgpException("no curve details found");
                }

                byte[] qVal;

                SXprUtilities.SkipOpenParenthesis(inputStream);

                type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (type.Equals("q"))
                {
                    qVal = SXprUtilities.ReadBytes(inputStream, inputStream.ReadByte());
                }
                else
                {
                    throw new PgpException("no q value found");
                }

                SXprUtilities.SkipCloseParenthesis(inputStream);

                byte[] dValue = getDValue(inputStream, keyProtectionRemoverFactory, curveName);
                // TODO: check SHA-1 hash.

                return new PgpSecretKey(new SecretKeyPacket(pubKey.PublicKeyPacket, SymmetricKeyAlgorithmTag.Null, null, null, new ECSecretBcpgKey(new BigInteger(1, dValue)).GetEncoded()), pubKey);
            }

            throw new PgpException("unknown key type found");
        }
        */
        /**
            * Parse a secret key from one of the GPG S expression keys.
            *
            * @return a secret key object.
            *//*
        public static PgpSecretKey parseSecretKeyFromSExpr(Stream inputStream, PbeProtectionRemoverFactory keyProtectionRemoverFactory, IKeyFingerPrintCalculator fingerPrintCalculator)
        {
            SXprUtilities.SkipOpenParenthesis(inputStream);

            String type;

            type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
            if (type.Equals("protected-private-key"))
            {
                SXprUtilities.SkipOpenParenthesis(inputStream);

                String curveName;

                String keyType = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (keyType.Equals("ecc"))
                {
                    SXprUtilities.SkipOpenParenthesis(inputStream);

                    String curveID = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                    curveName = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());

                    if (curveName.StartsWith("NIST "))
                    {
                        curveName = curveName.Substring("NIST ".Length);
                    }

                    SXprUtilities.SkipCloseParenthesis(inputStream);
                }
                else
                {
                    throw new PgpException("no curve details found");
                }

                byte[] qVal;

                SXprUtilities.SkipOpenParenthesis(inputStream);

                type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
                if (type.Equals("q"))
                {
                    qVal = SXprUtilities.ReadBytes(inputStream, inputStream.ReadByte());
                }
                else
                {
                    throw new PgpException("no q value found");
                }

                PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTag.ECDsa, new Date(), new ECDsaPublicBcpgKey(ECNamedCurveTable.GetOid(curveName), new BigInteger(1, qVal)));

                SXprUtilities.SkipCloseParenthesis(inputStream);

                byte[] dValue = getDValue(inputStream, keyProtectionRemoverFactory, curveName);
                // TODO: check SHA-1 hash.

                return new PgpSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTag.Null, null, null, new ECSecretBcpgKey(new BigInteger(1, dValue)).GetEncoded()), new PgpPublicKey(pubPacket, fingerPrintCalculator));
            }

            throw new PgpException("unknown key type found");
        }

        private static byte[] getDValue(Stream inputStream, PbeProtectionRemoverFactory keyProtectionRemoverFactory, String curveName)
        {
            String type;
            SXprUtilities.SkipOpenParenthesis(inputStream);

            String protection;
            S2k s2k;
            byte[] iv;
            byte[] secKeyData;

            type = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());
            if (type.Equals("protected"))
            {
                protection = SXprUtilities.ReadString(inputStream, inputStream.ReadByte());

                SXprUtilities.SkipOpenParenthesis(inputStream);

                s2k = SXprUtilities.ParseS2k(inputStream);

                iv = SXprUtilities.ReadBytes(inputStream, inputStream.ReadByte());

                SXprUtilities.SkipCloseParenthesis(inputStream);

                secKeyData = SXprUtilities.ReadBytes(inputStream, inputStream.ReadByte());
            }
            else
            {
                throw new PgpException("protected block not found");
            }

            PbeSecretKeyDecryptor keyDecryptor = keyProtectionRemoverFactory.createDecryptor(protection);

            // TODO: recognise other algorithms
            byte[] key = keyDecryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTag.Aes128, s2k);

            byte[] data = keyDecryptor.recoverKeyData(SymmetricKeyAlgorithmTag.Aes128, key, iv, secKeyData, 0, secKeyData.Length);

            //
            // parse the secret key S-expr
            //
            MemoryInputStream keyIn = new MemoryInputStream(data);

            SXprUtilities.SkipOpenParenthesis(keyIn);
            SXprUtilities.SkipOpenParenthesis(keyIn);
            SXprUtilities.SkipOpenParenthesis(keyIn);
            String name = SXprUtilities.ReadString(keyIn, keyIn.ReadByte());
            return SXprUtilities.ReadBytes(keyIn, keyIn.ReadByte());
        }
        */
    }
}
