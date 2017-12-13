using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections;
using System.IO;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>
    /// Class for parsing OpenSSL Pem encoded streams containing X509 certificates, PKCS8 encoded keys and PKCS7 objects.
    /// </summary>
    /// <remarks>
    /// In the case of PKCS7 objects the reader will return a CMS ContentInfo object. Public keys will be returned as
    /// well formed SubjectPublicKeyInfo objects, private keys will be returned as well formed PrivateKeyInfo objects.In the
    /// case of a private key a PemKeyPair will normally be returned if the encoding contains both the private and public
    /// key definition.CRLs, Certificates, PKCS#10 requests, and Attribute Certificates will generate the appropriate BC holder class.
    /// </remarks>
    public class OpenSslPemReader : PemReader
    {
        private readonly IDictionary parsers = Platform.CreateHashtable();

        /**
         * Create a new PemReader
         *
         * @param reader the Reader
         */
        public OpenSslPemReader(
            TextReader reader) : base(reader)
        {
            parsers.Add("CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
            parsers.Add("NEW CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
            parsers.Add("CERTIFICATE", new X509CertificateParser());
            parsers.Add("TRUSTED CERTIFICATE", new X509TrustedCertificateParser());
            parsers.Add("X509 CERTIFICATE", new X509CertificateParser());
            parsers.Add("X509 CRL", new X509CRLParser());
            parsers.Add("PKCS7", new PKCS7Parser());
            parsers.Add("CMS", new PKCS7Parser());
            parsers.Add("ATTRIBUTE CERTIFICATE", new X509AttributeCertificateParser());
            parsers.Add("EC PARAMETERS", new ECCurveParamsParser());
            parsers.Add("PUBLIC KEY", new PublicKeyParser());
            parsers.Add("RSA PUBLIC KEY", new RSAPublicKeyParser());
            parsers.Add("RSA PRIVATE KEY", new KeyPairParser(new RSAKeyPairParser()));
            parsers.Add("DSA PRIVATE KEY", new KeyPairParser(new DSAKeyPairParser()));
            parsers.Add("EC PRIVATE KEY", new KeyPairParser(new ECDSAKeyPairParser()));
            parsers.Add("ENCRYPTED PRIVATE KEY", new EncryptedPrivateKeyParser());
            parsers.Add("PRIVATE KEY", new PrivateKeyParser());
        }

        /// <summary>
        /// Return the next object in the reader, null if there are no more left.
        /// </summary>
        /// <returns>The next object in the reader, null at end of data.</returns>
        public Object ReadObject()
        {
            PemObject obj = ReadPemObject();

            if (obj != null)
            {
                String type = obj.Type;
                if (parsers.Contains(type))
                {
                    return ((PemObjectParser)parsers[type]).ParseObject(obj);
                }
                else
                {
                    throw new IOException("unrecognised object: " + type);
                }
            }

            return null;
        }

        private class KeyPairParser : PemObjectParser
        {
            private readonly PemKeyPairParser pemKeyPairParser;

            public KeyPairParser(PemKeyPairParser pemKeyPairParser)
            {
                this.pemKeyPairParser = pemKeyPairParser;
            }

            /**
             * Read a Key Pair
             */
            public object ParseObject(
                PemObject obj)
            {
                bool isEncrypted = false;
                String dekInfo = null;
                IList headers = obj.Headers;

                for (IEnumerator it = headers.GetEnumerator(); it.MoveNext();)
                {
                    PemHeader hdr = (PemHeader)it.Current;

                    if (hdr.Name.Equals("Proc-Type") && hdr.Value.Equals("4,ENCRYPTED"))
                    {
                        isEncrypted = true;
                    }
                    else if (hdr.Name.Equals("DEK-Info"))
                    {
                        dekInfo = hdr.Value;
                    }
                }

                //
                // extract the key
                //
                byte[] keyBytes = obj.GetContent();

                try
                {
                    if (isEncrypted)
                    {
                        return new OpenSslEncryptedObject(obj.Type, dekInfo, keyBytes, pemKeyPairParser);
                    }

                    return pemKeyPairParser.Parse(keyBytes);
                }
                catch (IOException e)
                {
                    if (isEncrypted)
                    {
                        throw new OpenSslPemParsingException("exception decoding - please check password and data.", e);
                    }
                    else
                    {
                        throw new OpenSslPemParsingException(e.Message, e);
                    }
                }
                catch (ArgumentException e)
                {
                    if (isEncrypted)
                    {
                        throw new OpenSslPemParsingException("exception decoding - please check password and data.", e);
                    }
                    else
                    {
                        throw new OpenSslPemParsingException(e.Message, e);
                    }
                }
            }
        }

        private class DSAKeyPairParser : PemKeyPairParser
        {
            public PemKeyPair Parse(byte[] encoding)
            {
                try
                {
                    Asn1Sequence seq = Asn1Sequence.GetInstance(encoding);

                    if (seq.Count != 6)
                    {
                        throw new OpenSslPemParsingException("malformed sequence in DSA private key");
                    }

                    //            DerInteger              v = (DerInteger)seq.getObjectAt(0);
                    DerInteger p = DerInteger.GetInstance(seq[1]);
                    DerInteger q = DerInteger.GetInstance(seq[2]);
                    DerInteger g = DerInteger.GetInstance(seq[3]);
                    DerInteger y = DerInteger.GetInstance(seq[4]);
                    DerInteger x = DerInteger.GetInstance(seq[5]);

                    return new PemKeyPair(
                        new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa, new DsaParameter(p.Value, q.Value, g.Value)), y),
                        new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa, new DsaParameter(p.Value, q.Value, g.Value)), x));
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException(
                        "problem creating DSA private key: " + e.ToString(), e);
                }
            }
        }

        private class ECDSAKeyPairParser : PemKeyPairParser
        {
            public PemKeyPair Parse(byte[] encoding)
            {
                try
                {
                    Asn1Sequence seq = Asn1Sequence.GetInstance(encoding);

                    ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(seq);
                    AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.GetParameters());
                    PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
                    SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pKey.GetPublicKey().GetBytes());

                    return new PemKeyPair(pubInfo, privInfo);
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException(
                        "problem creating EC private key: " + e.ToString(), e);
                }
            }
        }

        private class RSAKeyPairParser : PemKeyPairParser
        {
            public PemKeyPair Parse(byte[] encoding)
            {
                try
                {
                    Asn1Sequence seq = Asn1Sequence.GetInstance(encoding);

                    if (seq.Count != 9)
                    {
                        throw new OpenSslPemParsingException("malformed sequence in RSA private key");
                    }

                    RsaPrivateKeyStructure keyStruct = RsaPrivateKeyStructure.GetInstance(seq);

                    RsaPublicKeyStructure pubSpec = new RsaPublicKeyStructure(
                        keyStruct.Modulus, keyStruct.PublicExponent);

                    AlgorithmIdentifier algId = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);

                    return new PemKeyPair(new SubjectPublicKeyInfo(algId, pubSpec), new PrivateKeyInfo(algId, keyStruct));
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException(
                        "problem creating RSA private key: " + e.ToString(), e);
                }
            }
        }

        private class PublicKeyParser : PemObjectParser
        {
            public PublicKeyParser()
            {
            }

            public Object ParseObject(PemObject obj)
            {
                return SubjectPublicKeyInfo.GetInstance(obj.GetContent());
            }
        }

        private class RSAPublicKeyParser : PemObjectParser
        {
            public RSAPublicKeyParser()
            {
            }

            public Object ParseObject(PemObject obj)
            {
                try
                {
                    RsaPublicKeyStructure rsaPubStructure = RsaPublicKeyStructure.GetInstance(obj.GetContent());

                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance), rsaPubStructure);
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem extracting key: " + e.ToString(), e);
                }
            }
        }

        private class X509CertificateParser : PemObjectParser
        {
            /**
             * Reads in a X509Certificate.
             *
             * @return the X509Certificate
             */
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    return new X509Certificate(obj.GetContent());
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing cert: " + e.ToString(), e);
                }
            }
        }

        private class X509TrustedCertificateParser : PemObjectParser
        {
            /**
             * Reads in a X509Certificate.
             *
             * @return the X509Certificate
             */
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    return new X509TrustedCertificateBlock(obj.GetContent());
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing cert: " + e.ToString(), e);
                }
            }
        }

        private class X509CRLParser : PemObjectParser
        {
            /**
             * Reads in a X509CRL.
             *
             * @return the X509Certificate
             */
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    return new X509Crl(obj.GetContent());
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing cert: " + e.ToString(), e);
                }
            }
        }

        private class PKCS10CertificationRequestParser : PemObjectParser
        {
            /**
             * Reads in a PKCS10 certification request.
             *
             * @return the certificate request.
             */
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    return new Pkcs10CertificationRequest(obj.GetContent());
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing certrequest: " + e.ToString(), e);
                }
            }
        }

        private class PKCS7Parser : PemObjectParser
        {
            /**
             * Reads in a PKCS7 object. This returns a ContentInfo object suitable for use with the CMS
             * API.
             *
             * @return the X509Certificate
             */
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    Asn1InputStream aIn = new Asn1InputStream(obj.GetContent());

                    return ContentInfo.GetInstance(aIn.ReadObject());
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing PKCS7 object: " + e.ToString(), e);
                }
            }
        }

        private class X509AttributeCertificateParser : PemObjectParser
        {
            public Object ParseObject(PemObject obj)
            {
                return new X509V2AttributeCertificate(obj.GetContent());
            }
        }

        private class ECCurveParamsParser : PemObjectParser
        {
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    Object param = Asn1Object.FromByteArray(obj.GetContent());

                    if (param is DerObjectIdentifier)
                    {
                        return Asn1Object.FromByteArray(obj.GetContent());
                    }
                    else if (param is Asn1Sequence)
                    {
                        return X9ECParameters.GetInstance(param);
                    }
                    else
                    {
                        return null;  // implicitly CA
                    }
                }
                catch (IOException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("exception extracting EC named curve: " + e.ToString());
                }
            }
        }

        private class EncryptedPrivateKeyParser : PemObjectParser
        {
            public EncryptedPrivateKeyParser()
            {
            }

            /**
             * Reads in an EncryptedPrivateKeyInfo
             *
             * @return the X509Certificate
             */
            public Object ParseObject(PemObject obj)
            {
                try
                {
                    return new Pkcs8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.GetInstance(obj.GetContent()));
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing ENCRYPTED PRIVATE KEY: " + e.ToString(), e);
                }
            }
        }

        private class PrivateKeyParser : PemObjectParser
        {
            public PrivateKeyParser()
            {
            }

            public Object ParseObject(PemObject obj)
            {
                try
                {
                    return PrivateKeyInfo.GetInstance(obj.GetContent());
                }
                catch (Exception e)
                {
                    throw new OpenSslPemParsingException("problem parsing PRIVATE KEY: " + e.ToString(), e);
                }
            }
        }
    }
}
