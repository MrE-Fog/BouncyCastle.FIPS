using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.OpenPgp
{
    internal class PgpUtilities
    {
        private PgpUtilities()
        {
        }

        internal static MPInteger[] DsaSigToMpi(
            byte[] encoding)
        {
            DerInteger i1, i2;

            try
            {
                Asn1Sequence s = Asn1Sequence.GetInstance(encoding);

                i1 = DerInteger.GetInstance(s[0]);
                i2 = DerInteger.GetInstance(s[1]);
            }
            catch (IOException e)
            {
                throw new PgpException("exception encoding signature", e);
            }

            return new MPInteger[] { new MPInteger(i1.Value), new MPInteger(i2.Value) };
        }

        internal static MPInteger[] RsaSigToMpi(
            byte[] encoding)
        {
            return new MPInteger[] { new MPInteger(new BigInteger(1, encoding)) };
        }

        internal static byte[] MakeKeyFromPassPhrase(
            IDigestFactory<PgpDigestTypeIdentifier> digestFactory,
            SymmetricKeyAlgorithmTag algorithm,
            S2k s2k,
            char[] passPhrase)
        {
            int keySize = 0;

            switch (algorithm)
            {
                case SymmetricKeyAlgorithmTag.TripleDes:
                    keySize = 192;
                    break;
                case SymmetricKeyAlgorithmTag.Idea:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.Cast5:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.Blowfish:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.Safer:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.Des:
                    keySize = 64;
                    break;
                case SymmetricKeyAlgorithmTag.Aes128:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.Aes192:
                    keySize = 192;
                    break;
                case SymmetricKeyAlgorithmTag.Aes256:
                    keySize = 256;
                    break;
                case SymmetricKeyAlgorithmTag.Twofish:
                    keySize = 256;
                    break;
                case SymmetricKeyAlgorithmTag.Camellia128:
                    keySize = 128;
                    break;
                case SymmetricKeyAlgorithmTag.Camellia192:
                    keySize = 192;
                    break;
                case SymmetricKeyAlgorithmTag.Camellia256:
                    keySize = 256;
                    break;
                default:
                    throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }

            byte[] pBytes = Strings.ToUtf8ByteArray(passPhrase);
            byte[] keyBytes = new byte[(keySize + 7) / 8];

            int generatedBytes = 0;
            int loopCount = 0;

            if (s2k != null)
            {
                if (s2k.HashAlgorithm != digestFactory.AlgorithmDetails.Algorithm)
                {
                    throw new PgpException("s2k/digestFactory mismatch");
                }
            }
            else
            {
                if (digestFactory.AlgorithmDetails.Algorithm != HashAlgorithmTag.MD5)
                {
                    throw new PgpException("digestFactory not for MD5");
                }
            }

            IStreamCalculator<IBlockResult>  digestCalculator = digestFactory.CreateCalculator();
            Stream dOut = digestCalculator.Stream;

            try
            {
                while (generatedBytes < keyBytes.Length)
                {
                    if (s2k != null)
                    {
                        for (int i = 0; i != loopCount; i++)
                        {
                            dOut.WriteByte(0);
                        }

                        byte[] iv = s2k.GetIV();

                        switch (s2k.Type)
                        {
                            case S2k.Simple:
                                dOut.Write(pBytes, 0, pBytes.Length);
                                break;
                            case S2k.Salted:
                                dOut.Write(iv, 0, iv.Length);
                                dOut.Write(pBytes, 0, pBytes.Length);
                                break;
                            case S2k.SaltedAndIterated:
                                long count = s2k.IterationCount;
                                dOut.Write(iv, 0, iv.Length);
                                dOut.Write(pBytes, 0, pBytes.Length);

                                count -= iv.Length + pBytes.Length;

                                while (count > 0)
                                {
                                    if (count < iv.Length)
                                    {
                                        dOut.Write(iv, 0, (int)count);
                                        break;
                                    }
                                    else
                                    {
                                        dOut.Write(iv, 0, iv.Length);
                                        count -= iv.Length;
                                    }

                                    if (count < pBytes.Length)
                                    {
                                        dOut.Write(pBytes, 0, (int)count);
                                        count = 0;
                                    }
                                    else
                                    {
                                        dOut.Write(pBytes, 0, pBytes.Length);
                                        count -= pBytes.Length;
                                    }
                                }
                                break;
                            default:
                                throw new PgpException("unknown S2K type: " + s2k.Type);
                        }
                    }
                    else
                    {
                        for (int i = 0; i != loopCount; i++)
                        {
                            dOut.WriteByte((byte)0);
                        }

                        dOut.Write(pBytes, 0, pBytes.Length);
                    }

                    dOut.Close();

                    byte[] dig = digestCalculator.GetResult().Collect();

                    if (dig.Length > (keyBytes.Length - generatedBytes))
                    {
                        Array.Copy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
                    }
                    else
                    {
                        Array.Copy(dig, 0, keyBytes, generatedBytes, dig.Length);
                    }

                    generatedBytes += dig.Length;

                    loopCount++;
                }
            }
            catch (IOException e)
            {
                throw new PgpException("exception calculating digest: " + e.Message, e);
            }

            for (int i = 0; i != pBytes.Length; i++)
            {
                pBytes[i] = 0;
            }

            return keyBytes;
        }

        internal static byte[] MakeKeyFromPassPhrase(
            IDigestFactoryProvider<PgpDigestTypeIdentifier> digCalcProvider,
            SymmetricKeyAlgorithmTag algorithm,
            S2k s2k,
            char[] passPhrase)
        {
            IDigestFactory<PgpDigestTypeIdentifier> digestCalculator;

            if (s2k != null)
            {
                digestCalculator = digCalcProvider.CreateDigestFactory(new PgpDigestTypeIdentifier(s2k.HashAlgorithm));
            }
            else
            {
                digestCalculator = digCalcProvider.CreateDigestFactory(new PgpDigestTypeIdentifier(HashAlgorithmTag.MD5));
            }

            return MakeKeyFromPassPhrase(digestCalculator, algorithm, s2k, passPhrase);
        }
    }
}