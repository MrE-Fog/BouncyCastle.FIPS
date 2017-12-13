using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Parameters;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
    /**
     * Pem generator for the original set of Pem objects used in Open SSL.
     */
    internal class MiscPemGenerator : PemObjectGenerator
    {
        private static readonly DerObjectIdentifier[] dsaOids =
        {
        X9ObjectIdentifiers.IdDsa,
        OiwObjectIdentifiers.DsaWithSha1
    };

        private static readonly byte[] hexEncodingTable =
        {
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
        (byte)'8', (byte)'9', (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F'
    };

        private readonly Object obj;
        private readonly ICipherBuilder<DekInfo> encryptorBuilder;

        public MiscPemGenerator(Object o)
        {
            this.obj = o; 
            this.encryptorBuilder = null;
        }

        public MiscPemGenerator(Object o, ICipherBuilder<DekInfo> encryptorBuilder)
        {
            this.obj = o;
            this.encryptorBuilder = encryptorBuilder;
        }

        private PemObject createPemObject(Object o)
        {
            String type;
            byte[] encoding;

            if (o is PemObject)
            {
                return (PemObject)o;
            }
            if (o is PemObjectGenerator)
            {
                return ((PemObjectGenerator)o).Generate();
            }
            if (o is X509Certificate)
            {
                type = "CERTIFICATE";

                encoding = ((X509Certificate)o).GetEncoded();
            }
            else if (o is X509Crl)
            {
                type = "X509 CRL";

                encoding = ((X509Crl)o).GetEncoded();
            }
            else if (o is X509TrustedCertificateBlock)
            {
                type = "TRUSTED CERTIFICATE";

                encoding = ((X509TrustedCertificateBlock)o).GetEncoded();
            }
            else if (o is PrivateKeyInfo)
            {
                PrivateKeyInfo info = (PrivateKeyInfo)o;
                DerObjectIdentifier algOID = info.PrivateKeyAlgorithm.Algorithm;

                if (algOID.Equals(PkcsObjectIdentifiers.RsaEncryption))
                {
                    type = "RSA PRIVATE KEY";

                    encoding = info.ParsePrivateKey().ToAsn1Object().GetEncoded();
                }
                else if (algOID.Equals(dsaOids[0]) || algOID.Equals(dsaOids[1]))
                {
                    type = "DSA PRIVATE KEY";

                    DsaParameter p = DsaParameter.GetInstance(info.PrivateKeyAlgorithm.Parameters);
                    Asn1EncodableVector v = new Asn1EncodableVector();

                    v.Add(new DerInteger(0));
                    v.Add(new DerInteger(p.P));
                    v.Add(new DerInteger(p.Q));
                    v.Add(new DerInteger(p.G));

                    BigInteger x = DerInteger.GetInstance(info.ParsePrivateKey()).Value;
                    BigInteger y = p.G.ModPow(x, p.P);

                    v.Add(new DerInteger(y));
                    v.Add(new DerInteger(x));

                    encoding = new DerSequence(v).GetEncoded();
                }
                else if (algOID.Equals(X9ObjectIdentifiers.IdECPublicKey))
                {
                    type = "EC PRIVATE KEY";

                    encoding = info.ParsePrivateKey().ToAsn1Object().GetEncoded();
                }
                else
                {
                    type = "PRIVATE KEY";

                    encoding = info.GetEncoded();
                }
            }
            else if (o is SubjectPublicKeyInfo)
            {
                type = "PUBLIC KEY";

                encoding = ((SubjectPublicKeyInfo)o).GetEncoded();
            }
            /*
            else if (o is X509AttributeCertificateHolder)
            {
                type = "ATTRIBUTE CERTIFICATE";
                encoding = ((X509AttributeCertificateHolder)o).getEncoded();
            }
            */
            else if (o is Pkcs8EncryptedPrivateKeyInfo)
            {
                type = "ENCRYPTED PRIVATE KEY";
                encoding = ((Pkcs8EncryptedPrivateKeyInfo)o).GetEncoded();
            }
            else if (o is Pkcs10CertificationRequest)
            {
                type = "CERTIFICATE REQUEST";
                encoding = ((Pkcs10CertificationRequest)o).GetEncoded();
            }
            else if (o is ContentInfo)
            {
                type = "PKCS7";
                encoding = ((ContentInfo)o).GetEncoded();
            }
            else
            {
                throw new PemGenerationException("unknown object passed - can't encode.");
            }

            if (encryptorBuilder != null)
            {
                String dekAlgName = Platform.ToUpperInvariant(encryptorBuilder.AlgorithmDetails.Info);

                // Note: For backward compatibility
                if (dekAlgName.StartsWith("DESEDE"))
                {
                    dekAlgName = "DES-EDE3-CBC";
                }

                MemoryOutputStream bOut = new MemoryOutputStream();
                ICipher encryptor = encryptorBuilder.BuildCipher(bOut);
                
                using (var stream = encryptor.Stream)
                {
                    stream.Write(encoding, 0, encoding.Length);
                }

                byte[] encData = bOut.ToArray();

                IList headers = Platform.CreateArrayList();

                headers.Add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
                headers.Add(new PemHeader("DEK-Info", encryptorBuilder.AlgorithmDetails.Info));

                return new PemObject(type, headers, encData);
            }

            return new PemObject(type, encoding);
        }

        private String getHexEncoded(byte[] bytes)
        {
            char[] chars = new char[bytes.Length * 2];

            for (int i = 0; i != bytes.Length; i++)
            {
                int v = bytes[i] & 0xff;

                chars[2 * i] = (char)(hexEncodingTable[(v >> 4)]);
                chars[2 * i + 1] = (char)(hexEncodingTable[v & 0xf]);
            }

            return new String(chars);
        }

        public PemObject Generate()
        {
            try
            {
                return createPemObject(obj);
            }
            catch (IOException e)
            {
                throw new PemGenerationException("encoding exception: " + e.Message, e);
            }
        }
    }
}
